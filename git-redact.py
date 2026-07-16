#!/usr/bin/env python3
"""
git-redact — Audit and scrub git repositories for personal data.

Usage: python git-redact.py [options] [repo-path]

Options:
  -c, --config FILE   Path to config file (default: git-redact.conf.toml
                      in the repo root or next to this script)
  -n, --dry-run       Show what would be replaced/removed without doing it
  -h, --help          Show this help message

Exit codes:
  0 - No personal data found
  1 - Personal data found (see report)
  2 - Error (not a git repo, missing config, etc.)
"""

import argparse
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
    r"|^https?://",  # URLs
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
        "-r",
        "--report",
        action="store_true",
        help="Write a timestamped report to reports/",
    )
    return parser.parse_args()


def find_config(args_config, repo_path):
    """Resolve config file path."""
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

    print(
        "ERROR: Config file not found. Set GIT_REDACT_CONFIG, pass --config, or",
        file=sys.stderr,
    )
    print(
        "       place git-redact.conf.toml in the repo root or next to the script.",
        file=sys.stderr,
    )
    sys.exit(2)


def load_config(config_path):
    """Load and validate TOML config."""
    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    for section in ("paths", "patterns"):
        if section not in config:
            config[section] = []
    if "allow-emails" not in config:
        config["allow-emails"] = {"entries": []}

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


# ── Checks ─────────────────────────────────────────────────────────────────────


def action_label(action):
    """Return display label for an action."""
    return {
        "report": "FAIL",
        "warn": "WARN",
        "replace": "REPLACE",
        "remove": "REMOVE",
    }.get(action, action.upper())


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
    """Check for text patterns in git diff output (diff-aware)."""
    if diff_lines is None:
        diff_lines = get_diff_lines(repo_path)

    # Only search added lines for pattern matches
    added = get_added_lines(diff_lines)

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
        matches = [line for line in added if regex.search(line)]
        count = len(matches)

        if count > 0:
            print()
            print(f"=== {label} ({count} matches) [{action_label(action)}] ===")
            for m in matches[:20]:
                print(m)
            findings.append({"label": label, "action": action, "count": count})

    return findings


def check_entropy(repo_path, diff_lines):
    """Detect high-entropy strings that may be secrets/tokens."""
    added = get_added_lines(diff_lines)
    findings = {}

    for line in added:
        content = line[1:]  # strip leading +
        for match in CANDIDATE_RE.finditer(content):
            candidate = match.group()

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


def main():
    args = parse_args()
    repo_path = Path(args.repo).resolve()

    # Validate repo
    if not (repo_path / ".git").is_dir():
        print(f"ERROR: {repo_path} is not a git repository", file=sys.stderr)
        sys.exit(2)

    # Find and load config
    config_path = find_config(args.config, repo_path)
    print(f"Using config: {config_path}")
    config = load_config(config_path)

    print(f"Auditing git history in: {repo_path}")
    print("Searching all commits across all refs...")
    print()

    all_findings = []

    # Fetch diff once for all pattern and entropy checks
    diff_lines = get_diff_lines(repo_path)

    # ── Paths ──
    path_entries = config.get("paths", [])
    all_findings.extend(check_paths(repo_path, path_entries))

    # ── Patterns (diff-aware: only added lines) ──
    pattern_entries = config.get("patterns", [])
    all_findings.extend(check_patterns(repo_path, pattern_entries, diff_lines))

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
        report_content = "\n".join(lines)
        write_report(report_content)

    if not failures:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
