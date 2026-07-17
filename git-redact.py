#!/usr/bin/env python3
"""
git-redact — Audit and scrub git repositories for personal data.

Usage: python git-redact.py [options] [repo-path]

Options:
  -c, --config FILE       Path to config file (default: git-redact.conf.toml
                           in the repo root or next to this script)
  -n, --dry-run           Show what would be replaced/removed without doing it
  --no-builtin            Skip built-in patterns (only use your config)
  --no-entropy            Disable entropy-based secret detection
  -r, --report            Write a timestamped report to reports/
  -h, --help              Show this help message

Exit codes:
  0 - No personal data found
  1 - Personal data found (see report)
  2 - Error (not a git repo, missing config, etc.)
"""

import argparse
import io
import math
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import tomllib

SCRIPT_DIR = Path(__file__).resolve().parent

# ── Entropy detection ──────────────────────────────────────────────────────────

# Minimum length of a string to consider for entropy analysis.
# Short strings have low entropy by nature and produce too many false positives.
ENTROPY_MIN_LENGTH = 20

# Shannon entropy threshold (bits per character). Values above this are likely
# secrets/tokens. Base64-encoded data averages ~6 bits/char, hex ~4 bits/char.
# Real English text averages ~4.7 bits/char but over longer strings, so we set
# the threshold at 4.5 for strings of 20+ chars to catch most secrets while
# avoiding common prose.
ENTROPY_THRESHOLD = 4.5

# Regex to extract candidate strings from diff lines. Matches long runs of
# characters that look like keys, tokens, or encoded data.
CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-.]{20,}")

# Known patterns that are high-entropy but not secrets (reducing false positives).
ENTROPY_ALLOWLIST_RE = re.compile(
    r"^(?:[A-Za-z0-9+/=_\-.]*\.){2,}[A-Za-z]{2,}$"  # domain names
    r"|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"  # IP addresses
    r"|^[\w.\-]+@[\w.\-]+\.\w+$"  # email addresses
    r"|^[A-Fa-f0-9]{40}$"  # SHA-1 hashes (commit hashes)
    r"|^[A-Fa-f0-9]{64}$"  # SHA-256 hashes
    r"|^https?://"  # URLs
    r"|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"  # UUIDs
    r"|.*nix/store/[a-z0-9]{32}-"  # Nix store paths (with any prefix)
    r"|^sha[0-9]+-[A-Za-z0-9+/=]+$"  # SRI hashes (sha256-..., sha512-...)
    r"|^[0-9]+\.[0-9]+\.[0-9]+[-+]",  # semver with pre-release/build metadata
    re.IGNORECASE,
)


def shannon_entropy(s):
    """Calculate Shannon entropy of a string in bits per character."""
    if len(s) <= 1:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_high_entropy_strings(diff_lines):
    """Find high-entropy strings in diff output that aren't caught by patterns."""
    findings = {}  # string -> count, for deduplication

    for line in diff_lines:
        # Only look at added lines
        if not line.startswith("+") or line.startswith("+++"):
            continue

        # Strip the leading '+'
        content = line[1:]

        for match in CANDIDATE_RE.finditer(content):
            candidate = match.group()

            # Skip purely alphabetic strings (long words, camelCase identifiers)
            if candidate.isalpha():
                continue

            # Skip known non-secret patterns
            if ENTROPY_ALLOWLIST_RE.match(candidate):
                continue

            # Skip if too short
            if len(candidate) < ENTROPY_MIN_LENGTH:
                continue

            # Calculate entropy
            entropy = shannon_entropy(candidate)
            if entropy >= ENTROPY_THRESHOLD:
                findings[candidate] = findings.get(candidate, 0) + 1

    return findings


# ── Config and CLI ────────────────────────────────────────────────────────────


def parse_args():
    parser = argparse.ArgumentParser(
        prog="git-redact",
        description="Audit git repositories for personal data.",
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=os.getcwd(),
        help="Path to the git repo (default: current directory)",
    )
    parser.add_argument("-c", "--config", default=None, help="Path to config file")
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Show what would be replaced/removed without doing it",
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable entropy-based secret detection",
    )
    parser.add_argument(
        "--no-builtin",
        action="store_true",
        help="Skip built-in patterns (only use your config)",
    )
    parser.add_argument(
        "-r",
        "--report",
        action="store_true",
        help="Write a timestamped report to reports/",
    )
    return parser.parse_args()


def find_config(args_config, repo_path):
    """Resolve config file path.

    Returns the path to a user config file, or None if no user config
    exists (builtins will still be loaded by load_config).
    """
    if args_config:
        config = Path(args_config)
        if not config.is_file():
            print(f"ERROR: Config file not found: {config}", file=sys.stderr)
            sys.exit(2)
        return config

    env_config = os.environ.get("GIT_REDACT_CONFIG")
    if env_config:
        config = Path(env_config)
        if not config.is_file():
            print(f"ERROR: Config file not found: {config}", file=sys.stderr)
            sys.exit(2)
        return config

    for candidate in [
        Path(repo_path) / "git-redact.conf.toml",
        SCRIPT_DIR / "git-redact.conf.toml",
    ]:
        if candidate.is_file():
            return candidate

    # No user config found — builtins will still be used
    return None


BUILTIN_CONFIG_PATH = SCRIPT_DIR / "git-redact.conf.builtin.toml"


def load_config(config_path, no_builtin=False):
    """Load builtin patterns, then merge user config on top.

    Built-in patterns (private keys, API tokens, etc.) are loaded from
    git-redact.conf.builtin.toml unless no_builtin is True.
    The user's config is merged on top:

    - paths/patterns with new labels are appended
    - paths/patterns with a label that matches a builtin override it
      (with a notification printed to stderr)
    - allow-emails entries are appended; action/replace-with override
    """
    # Load builtins first (unless --no-builtin)
    config = {"paths": [], "patterns": [], "allow-emails": {"entries": []}}
    if not no_builtin and BUILTIN_CONFIG_PATH.is_file():
        with open(BUILTIN_CONFIG_PATH, "rb") as f:
            builtin = tomllib.load(f)
        for section in ("paths", "patterns"):
            config[section] = builtin.get(section, [])
        if "allow-emails" in builtin:
            config["allow-emails"] = builtin["allow-emails"]

    # Merge user config on top (if present)
    if config_path is not None:
        with open(config_path, "rb") as f:
            user = tomllib.load(f)

        for section in ("paths", "patterns"):
            user_entries = user.get(section, [])
            # Collect labels from user entries that override builtins
            user_labels = {e.get("label") for e in user_entries if "label" in e}
            # Remove builtin entries whose labels are overridden
            if user_labels:
                builtin_labels = {
                    e.get("label") for e in config[section] if "label" in e
                }
                overridden = user_labels & builtin_labels
                if overridden:
                    for label in sorted(overridden):
                        print(
                            f"  Override: [{section}] '{label}' replaced by user config",
                            file=sys.stderr,
                        )
                    config[section] = [
                        e for e in config[section] if e.get("label") not in overridden
                    ]
            # Append all user entries
            config[section].extend(user_entries)

        if "allow-emails" in user:
            if "entries" in user["allow-emails"]:
                config["allow-emails"].setdefault("entries", []).extend(
                    user["allow-emails"]["entries"]
                )
            if "action" in user["allow-emails"]:
                config["allow-emails"]["action"] = user["allow-emails"]["action"]
            if "replace-with" in user["allow-emails"]:
                config["allow-emails"]["replace-with"] = user["allow-emails"][
                    "replace-with"
                ]

    return config


# ── Git helpers ────────────────────────────────────────────────────────────────


def git_cmd(repo_path, *args):
    """Run a git command and return stdout."""
    result = subprocess.run(
        ["git", "-C", str(repo_path)] + list(args),
        capture_output=True,
        text=True,
        errors="replace",
    )
    return result.stdout


def get_diff_lines(repo_path):
    """Fetch full diff output from all commits, split into lines.

    Returns only added lines (prefixed with +) for diff-aware analysis,
    but also returns all lines for pattern matching on context.
    """
    result = subprocess.run(
        ["git", "-C", str(repo_path), "log", "--all", "-p"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )
    return result.stdout.splitlines()


def get_added_lines(diff_lines):
    """Extract only lines that were added (start with +, not +++)."""
    return [
        line
        for line in diff_lines
        if line.startswith("+") and not line.startswith("+++")
    ]


def get_commit_messages(repo_path):
    """Fetch all commit and tag messages from all refs."""
    result = subprocess.run(
        ["git", "-C", str(repo_path), "log", "--all", "--format=%s%n%b"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )
    return result.stdout.splitlines()


# ── Checks ─────────────────────────────────────────────────────────────────────


def action_label(action):
    """Return display label for an action."""
    return {
        "report": "FAIL",
        "warn": "WARN",
        "replace": "REPLACE",
        "remove": "REMOVE",
    }.get(action, action.upper())


def compile_combined_pattern(entries):
    """Compile multiple pattern entries into a single combined regex.

    Returns a tuple of (combined_regex, group_map) where:
    - combined_regex has each pattern as a named group (p0, p1, ...)
    - group_map maps group names to their original entry dicts
    Patterns with (?i) prefix use inline (?i:...) syntax for per-group
    case-insensitivity within the combined regex.
    """
    parts = []
    group_map = {}
    for i, entry in enumerate(entries):
        name = f"p{i}"
        pattern = entry["pattern"]
        if pattern.startswith("(?i)"):
            inner = pattern[4:]
            part = f"(?P<{name}>(?i:{inner}))"
        else:
            part = f"(?P<{name}>{pattern})"
        parts.append(part)
        group_map[name] = entry
    combined = "|".join(parts)
    return re.compile(combined), group_map


def check_paths(repo_path, entries):
    """Check for sensitive paths in git history."""
    findings = []
    for entry in entries:
        label = entry.get("label", entry["pattern"])
        pattern = entry["pattern"]
        action = entry.get("action", "report")

        output = git_cmd(
            repo_path, "log", "--all", "--name-only", "--pretty=format:", "--", pattern
        )
        files = sorted(set(f for f in output.splitlines() if f.strip()))
        count = len(files)

        if count > 0:
            print()
            print(
                f"=== {label} ({count} unique file entries) [{action_label(action)}] ==="
            )
            for f in files[:30]:
                print(f)
            findings.append({"label": label, "action": action, "count": count})

    return findings


def check_patterns(repo_path, entries, diff_lines=None):
    """Check for text patterns in git diff output (diff-aware).

    Uses a single-pass combined regex for performance: all patterns are
    compiled into one alternation, and each added line is scanned once.
    """
    if diff_lines is None:
        diff_lines = get_diff_lines(repo_path)

    # Only search added lines for pattern matches
    added = get_added_lines(diff_lines)

    if not entries:
        return []

    combined_regex, group_map = compile_combined_pattern(entries)

    # Single pass over added lines
    pattern_matches = {f"p{i}": [] for i in range(len(entries))}
    for line in added:
        matched_groups = set()
        for match in combined_regex.finditer(line):
            group_name = match.lastgroup
            if (
                group_name
                and group_name in group_map
                and group_name not in matched_groups
            ):
                pattern_matches[group_name].append(line)
                matched_groups.add(group_name)

    # Produce output in the same format as the original per-pattern loop
    findings = []
    for i, entry in enumerate(entries):
        name = f"p{i}"
        label = entry.get("label", entry["pattern"])
        action = entry.get("action", "report")
        matches = pattern_matches[name]
        count = len(matches)
        if count > 0:
            print()
            print(f"=== {label} ({count} matches) [{action_label(action)}] ===")
            for m in matches[:20]:
                print(m)
            findings.append({"label": label, "action": action, "count": count})

    return findings


def check_commit_messages(repo_path, entries, commit_messages=None):
    """Check for text patterns in commit messages."""
    if commit_messages is None:
        commit_messages = get_commit_messages(repo_path)

    if not entries:
        return []

    findings = []
    for entry in entries:
        label = entry.get("label", entry["pattern"])
        pattern = entry["pattern"]
        action = entry.get("action", "report")

        # Compile with case-insensitive flag if pattern starts with (?i)
        flags = 0
        search_pattern = pattern
        if search_pattern.startswith("(?i)"):
            flags = re.IGNORECASE
            search_pattern = search_pattern[4:]

        regex = re.compile(search_pattern, flags)
        matches = [line for line in commit_messages if regex.search(line)]
        count = len(matches)

        if count > 0:
            print()
            print(
                f"=== {label} in commit messages ({count} matches) [{action_label(action)}] ==="
            )
            for m in matches[:20]:
                print(f"  {m}")
            findings.append(
                {
                    "label": f"{label} [commit messages]",
                    "action": action,
                    "count": count,
                }
            )

    return findings


def check_entropy(repo_path, diff_lines):
    """Detect high-entropy strings that may be secrets/tokens."""
    added = get_added_lines(diff_lines)
    findings = {}

    for line in added:
        content = line[1:]  # strip leading +
        for match in CANDIDATE_RE.finditer(content):
            candidate = match.group()

            # Skip purely alphabetic strings (long words, camelCase identifiers)
            if candidate.isalpha():
                continue

            # Skip known non-secret patterns
            if ENTROPY_ALLOWLIST_RE.match(candidate):
                continue

            if len(candidate) < ENTROPY_MIN_LENGTH:
                continue

            entropy = shannon_entropy(candidate)
            if entropy >= ENTROPY_THRESHOLD:
                findings[candidate] = findings.get(candidate, 0) + 1

    return findings


def check_emails(repo_path, allow_config):
    """Check git author emails against allow-list."""
    entries = allow_config.get("entries", [])
    action = allow_config.get("action", "report")

    print()
    print("=== Git author emails ===")
    emails_output = git_cmd(repo_path, "log", "--all", "--format=%ae")
    emails = sorted(set(emails_output.splitlines()))
    for email in emails:
        print(email)

    print()
    print("=== Git author names ===")
    names_output = git_cmd(repo_path, "log", "--all", "--format=%an")
    names = sorted(set(names_output.splitlines()))
    for name in names:
        print(name)
    print()

    if not entries:
        return []

    # Build exclusion regex from allow-list
    allow_patterns = []
    for entry in entries:
        if isinstance(entry, str):
            allow_patterns.append(entry)
        else:
            allow_patterns.append(entry["email"])

    allow_regex = "|".join(f"^({p})$" for p in allow_patterns)

    personal_emails = []
    for email in emails:
        if not re.match(allow_regex, email):
            personal_emails.append(email)

    if personal_emails:
        print("WARNING: Non-allowlisted emails found in commit history:")
        for email in personal_emails:
            print(f"  {email}")
        return [
            {
                "label": "Non-allowlisted emails",
                "action": action,
                "count": len(personal_emails),
            }
        ]

    return []


# ── Main ────────────────────────────────────────────────────────────────────────


def write_report(content):
    """Write a timestamped report file to the reports/ directory next to the script."""
    from datetime import datetime

    report_dir = SCRIPT_DIR / "reports"
    report_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    report_file = report_dir / f"git-redact-{timestamp}.log"

    report_file.write_text(content, errors="replace")
    print(f"\nReport written to: {report_file}")


class TeeWriter:
    """Writes to both a real stream and a capture buffer."""

    def __init__(self, real_stream, capture_buffer):
        self._real = real_stream
        self._buf = capture_buffer

    def write(self, text):
        self._real.write(text)
        self._buf.write(text)

    def flush(self):
        self._real.flush()
        self._buf.flush()

    def fileno(self):
        return self._real.fileno()

    @property
    def encoding(self):
        return self._real.encoding


def main():
    args = parse_args()
    repo_path = Path(args.repo).resolve()

    # Validate repo
    if not (repo_path / ".git").is_dir():
        print(f"ERROR: {repo_path} is not a git repository", file=sys.stderr)
        sys.exit(2)

    # Find and load config
    config_path = find_config(args.config, repo_path)
    if config_path:
        print(f"Using config: {config_path}")
    else:
        print("No user config found \u2014 using built-in patterns only")
    config = load_config(config_path, no_builtin=args.no_builtin)

    print(f"Auditing git history in: {repo_path}")
    print("Searching all commits across all refs...")
    print()

    all_findings = []

    # Capture detailed output for the report
    log_buffer = io.StringIO()
    original_stdout = sys.stdout
    sys.stdout = TeeWriter(original_stdout, log_buffer)

    # Fetch diff once for all pattern and entropy checks
    diff_lines = get_diff_lines(repo_path)
    commit_messages = get_commit_messages(repo_path)

    # ── Paths ──
    path_entries = config.get("paths", [])
    all_findings.extend(check_paths(repo_path, path_entries))

    # ── Patterns (diff-aware: only added lines) ──
    pattern_entries = config.get("patterns", [])
    all_findings.extend(check_patterns(repo_path, pattern_entries, diff_lines))

    # ── Commit messages ──
    all_findings.extend(
        check_commit_messages(repo_path, pattern_entries, commit_messages)
    )

    # ── Entropy detection ──
    if not args.no_entropy:
        print()
        print("=== High-entropy strings (potential secrets) ===")
        print(
            f"  threshold: {ENTROPY_THRESHOLD} bits/char, min length: {ENTROPY_MIN_LENGTH})"
        )
        entropy_findings = check_entropy(repo_path, diff_lines)
        if entropy_findings:
            for candidate, count in sorted(
                entropy_findings.items(), key=lambda x: -x[1]
            ):
                entropy = shannon_entropy(candidate)
                print(
                    f"  [{entropy:.1f} b/pc] {candidate[:80]}{'...' if len(candidate) > 80 else ''} (x{count})"
                )
            all_findings.append(
                {
                    "label": "High-entropy strings",
                    "action": "warn",  # always warn, never fail
                    "count": sum(entropy_findings.values()),
                }
            )
        else:
            print("  None found")

    # ── Emails ──
    allow_config = config.get("allow-emails", {"entries": []})
    all_findings.extend(check_emails(repo_path, allow_config))

    # ── Future: replace/remove actions ──
    replace_remove = [f for f in all_findings if f["action"] in ("replace", "remove")]
    if replace_remove and not args.dry_run:
        print()
        print(
            "NOTE: The following entries have replace/remove actions but history rewriting"
        )
        print("is not yet implemented. Use --dry-run to preview what would change.")
        for f in replace_remove:
            print(f"  - {f['label']} ({f['action'].upper()})")

    if replace_remove and args.dry_run:
        print()
        print("=== Dry run: would apply the following changes ===")
        for f in replace_remove:
            print(f"  - {f['label']} ({f['action'].upper()})")

    # ── Summary ──
    print()
    print("=" * 42)
    failures = [f for f in all_findings if f["action"] == "report"]
    if not failures:
        result = "PASS: No personal data found in git history"
        print(result)
    else:
        result = "FAIL: Personal data found in git history (see above)"
        print(result)

    # ── Write report if requested ──
    # Restore stdout before writing report so print() in write_report
    # goes only to the real terminal, not into the capture buffer.
    sys.stdout = original_stdout
    if args.report:
        from datetime import datetime

        lines = []
        lines.append("git-redact report")
        lines.append("=" * 42)
        lines.append(f"Repository: {repo_path}")
        lines.append(f"Config: {config_path}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append(f"Findings: {len(all_findings)} total")
        lines.append(
            f"  FAIL: {len([f for f in all_findings if f['action'] == 'report'])}"
        )
        lines.append(
            f"  WARN: {len([f for f in all_findings if f['action'] == 'warn'])}"
        )
        lines.append(
            f"  REPLACE: {len([f for f in all_findings if f['action'] == 'replace'])}"
        )
        lines.append(
            f"  REMOVE: {len([f for f in all_findings if f['action'] == 'remove'])}"
        )
        lines.append("")
        lines.append(f"Result: {result}")
        lines.append("")
        lines.append("=" * 42)
        lines.append("")
        lines.append("Findings:")
        for f in all_findings:
            lines.append(f"  [{action_label(f['action'])}] {f['label']} ({f['count']})")
        # Append the full detailed log captured from stdout
        detailed_log = log_buffer.getvalue()
        if detailed_log:
            lines.append("")
            lines.append("=" * 42)
            lines.append("=" * 42)
            lines.append("")
            lines.append("Detailed log:")
            lines.append("")
            lines.append(detailed_log.rstrip())
        report_content = "\n".join(lines)
        write_report(report_content)

    if not failures:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
