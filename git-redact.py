#!/usr/bin/env python3
"""git-redact -- Audit and scrub git repositories for personal data.

Usage: python git-redact.py [options] [repo-path]

Options:
  -c, --config FILE       Path to config file (default: git-redact.conf.toml
                           in the repo root or next to this script)
  --no-builtin            Skip built-in patterns (only use your config)
  --no-binary             Skip binary files in diff output
  --no-entropy            Disable entropy-based secret detection
  --pipeline              Output findings as JSON to stdout (for CI/CD)
  --preview               Preview what rewrite would change (no modifications)
  --rewrite               Rewrite git history to redact matched data
  -y                      Skip confirmation prompt for --rewrite
  -r, --report            Write a timestamped report to reports/
  -h, --help              Show this help message

Modes:
  (default)               Audit only — scan and report findings
  --pipeline              Audit with JSON output — for CI/CD and hooks
  --preview               Show what rewrite would change — no modifications
  --rewrite               Rewrite git history (with confirmation and countdown)

  --pipeline is mutually exclusive with --preview and --rewrite.
  --preview is mutually exclusive with --rewrite.

Exit codes:
  0 - No personal data found
  1 - Personal data found (see report)
  2 - Error (not a git repo, missing config, etc.)
"""

import argparse
import io
import json
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
        "--no-binary",
        action="store_true",
        help="Skip binary files in diff output",
    )
    parser.add_argument(
        "--pipeline",
        action="store_true",
        help="Output findings as JSON to stdout (for CI/CD)",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Preview what rewrite would change (no modifications)",
    )
    parser.add_argument(
        "--rewrite",
        action="store_true",
        help="Rewrite git history to redact matched data",
    )
    parser.add_argument(
        "-y",
        action="store_true",
        help="Skip confirmation prompt for --rewrite (use with caution)",
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

    - paths/patterns/git-author-email/git-author-name with new labels are appended;
      same-label entries override builtins (with stderr notification)
    - git-author-emails/git-author-names: entries are appended; action/replace-with
      override
    - After merging, replace-with values from singular git-author-email/name
      entries (action=replace) are auto-whitelisted in the plural entries
    """
    # Load builtins first (unless --no-builtin)
    config = {
        "paths": [],
        "patterns": [],
        "git-author-email": [],
        "git-author-name": [],
        "git-author-emails": {"entries": []},
        "git-author-names": {"entries": []},
    }
    if not no_builtin and BUILTIN_CONFIG_PATH.is_file():
        with open(BUILTIN_CONFIG_PATH, "rb") as f:
            builtin = tomllib.load(f)
        for section in ("paths", "patterns", "git-author-email", "git-author-name"):
            config[section] = builtin.get(section, [])
        for plural in ("git-author-emails", "git-author-names"):
            if plural in builtin:
                config[plural] = builtin[plural]

    # Merge user config on top (if present)
    if config_path is not None:
        with open(config_path, "rb") as f:
            user = tomllib.load(f)

        for section in ("paths", "patterns", "git-author-email", "git-author-name"):
            user_entries = user.get(section, [])
            user_labels = {e.get("label") for e in user_entries if "label" in e}
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
            config[section].extend(user_entries)

        for plural in ("git-author-emails", "git-author-names"):
            if plural in user:
                if "entries" in user[plural]:
                    config[plural].setdefault("entries", []).extend(
                        user[plural]["entries"]
                    )
                if "action" in user[plural]:
                    config[plural]["action"] = user[plural]["action"]
                if "replace-with" in user[plural]:
                    config[plural]["replace-with"] = user[plural]["replace-with"]

    # Auto-whitelist: add replace-with values from singular entries to plural entries
    for singular, plural, field in [
        ("git-author-email", "git-author-emails", "email"),
        ("git-author-name", "git-author-names", "name"),
    ]:
        existing = {e[field] for e in config[plural].get("entries", []) if field in e}
        for entry in config.get(singular, []):
            if entry.get("action") == "replace" and "replace-with" in entry:
                escaped = re.escape(entry["replace-with"])
                if escaped not in existing:
                    config[plural].setdefault("entries", []).append({field: escaped})
                    existing.add(escaped)

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


def filter_binary_sections(diff_lines):
    """Remove diff sections for binary files.

    A diff section starts with 'diff --git' and ends at the next
    'diff --git' line or end of output. Sections containing a line
    starting with 'Binary files' are removed entirely.

    Lines before the first diff section (commit headers, etc.) are
    always kept.
    """
    result = []
    current_section = []
    in_diff_section = False

    for line in diff_lines:
        if line.startswith("diff --git"):
            # Finish the previous section
            if in_diff_section and current_section:
                if not any(l.startswith("Binary files") for l in current_section):
                    result.extend(current_section)
            elif current_section:
                # Pre-diff lines (commit headers), always keep
                result.extend(current_section)
            # Start new section
            current_section = [line]
            in_diff_section = True
        else:
            current_section.append(line)

    # Handle last section
    if current_section:
        if in_diff_section:
            if not any(l.startswith("Binary files") for l in current_section):
                result.extend(current_section)
        else:
            result.extend(current_section)

    return result


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

    # Produce deduplicated output
    findings = []
    for i, entry in enumerate(entries):
        name = f"p{i}"
        label = entry.get("label", entry["pattern"])
        action = entry.get("action", "report")
        matches = pattern_matches[name]
        count = len(matches)
        if count > 0:
            # Group identical lines by content, sorted by frequency
            seen = {}
            for m in matches:
                seen[m] = seen.get(m, 0) + 1
            unique = len(seen)
            print()
            print(
                f"=== {label} ({unique} unique, {count} total) [{action_label(action)}] ==="
            )
            for m, c in sorted(seen.items(), key=lambda x: -x[1]):
                print(f"  [x{c}] {m}")
            findings.append(
                {"label": label, "action": action, "count": count, "unique": unique}
            )

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
            # Deduplicate commit messages
            seen = {}
            for m in matches:
                seen[m] = seen.get(m, 0) + 1
            unique = len(seen)
            print()
            print(
                f"=== {label} in commit messages ({unique} unique, {count} total) [{action_label(action)}] ==="
            )
            for m, c in sorted(seen.items(), key=lambda x: -x[1]):
                print(f"  [x{c}] {m}")
            findings.append(
                {
                    "label": f"{label} [commit messages]",
                    "action": action,
                    "count": count,
                    "unique": unique,
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


def check_author_emails(repo_path, singular_entries, plural_config):
    """Check git author emails against singular patterns and plural allow-list.

    singular_entries: list of [[git-author-email]] entries (like patterns).
    plural_config: the [git-author-emails] section with entries whitelist
                   and action/replace-with for non-allowlisted emails.
    """
    emails_output = git_cmd(repo_path, "log", "--all", "--format=%ae")
    emails = sorted(set(emails_output.splitlines()))
    if not emails:
        return []

    findings = []

    print()
    print("=== Git author emails ===")
    for email in emails:
        print(email)

    # Singular entries: check each pattern against emails
    for entry in singular_entries:
        label = entry.get("label", entry.get("email", "email pattern"))
        pattern = entry.get("email", entry.get("pattern", ""))
        action = entry.get("action", "report")

        flags = re.IGNORECASE if pattern.startswith("(?i)") else 0
        search_pattern = pattern[4:] if pattern.startswith("(?i)") else pattern
        regex = re.compile(search_pattern, flags)

        matches = [e for e in emails if regex.search(e)]
        count = len(matches)
        if count > 0:
            seen = {}
            for m in matches:
                seen[m] = seen.get(m, 0) + 1
            unique = len(seen)
            print()
            print(
                f"=== {label} ({unique} unique, {count} total) [{action_label(action)}] ==="
            )
            for m, c in sorted(seen.items(), key=lambda x: -x[1]):
                print(f"  [x{c}] {m}")
            findings.append(
                {"label": label, "action": action, "count": count, "unique": unique}
            )

    # Plural section: check emails against allow-list
    entries = plural_config.get("entries", [])
    action = plural_config.get("action", "report")

    if entries:
        allow_patterns = [e["email"] if isinstance(e, dict) else e for e in entries]
        allow_regex = "|".join(f"^({p})$" for p in allow_patterns)

        personal_emails = []
        for email in emails:
            if not re.match(allow_regex, email):
                personal_emails.append(email)

        if personal_emails:
            print()
            print("WARNING: Non-allowlisted emails found in commit history:")
            for email in personal_emails:
                print(f"  {email}")
            findings.append(
                {
                    "label": "Non-allowlisted emails",
                    "action": action,
                    "count": len(personal_emails),
                    "unique": len(personal_emails),
                }
            )

    return findings


def check_author_names(repo_path, singular_entries, plural_config):
    """Check git author names against singular patterns and plural allow-list.

    Same structure as check_author_emails but for names.
    """
    names_output = git_cmd(repo_path, "log", "--all", "--format=%an")
    names = sorted(set(names_output.splitlines()))
    if not names:
        return []

    findings = []

    print()
    print("=== Git author names ===")
    for name in names:
        print(name)

    # Singular entries: check each pattern against names
    for entry in singular_entries:
        label = entry.get("label", entry.get("name", "name pattern"))
        pattern = entry.get("name", entry.get("pattern", ""))
        action = entry.get("action", "report")

        flags = re.IGNORECASE if pattern.startswith("(?i)") else 0
        search_pattern = pattern[4:] if pattern.startswith("(?i)") else pattern
        regex = re.compile(search_pattern, flags)

        matches = [n for n in names if regex.search(n)]
        count = len(matches)
        if count > 0:
            seen = {}
            for m in matches:
                seen[m] = seen.get(m, 0) + 1
            unique = len(seen)
            print()
            print(
                f"=== {label} ({unique} unique, {count} total) [{action_label(action)}] ==="
            )
            for m, c in sorted(seen.items(), key=lambda x: -x[1]):
                print(f"  [x{c}] {m}")
            findings.append(
                {"label": label, "action": action, "count": count, "unique": unique}
            )

    # Plural section: check names against allow-list
    entries = plural_config.get("entries", [])
    action = plural_config.get("action", "report")

    if entries:
        allow_patterns = [e["name"] if isinstance(e, dict) else e for e in entries]
        allow_regex = "|".join(f"^({p})$" for p in allow_patterns)

        personal_names = []
        for name in names:
            if not re.match(allow_regex, name):
                personal_names.append(name)

        if personal_names:
            print()
            print("WARNING: Non-allowlisted names found in commit history:")
            for name in personal_names:
                print(f"  {name}")
            findings.append(
                {
                    "label": "Non-allowlisted names",
                    "action": action,
                    "count": len(personal_names),
                    "unique": len(personal_names),
                }
            )

    return findings


# ── History rewriting ────────────────────────────────────────────────────────────


def collect_rewrite_rules(config):
    """Collect all rewrite rules from config entries with replace/remove actions.

    Returns a dict with:
      blob_replacements: [(compiled_regex, replacement_bytes), ...]
      message_replacements: [(compiled_regex, replacement_bytes), ...]
      path_removals: [pattern, ...]
      path_renames: [(old_pattern, new_pattern), ...]
      email_singular_rules: [(compiled_regex, replacement_bytes), ...]
      email_catchall_replace: string or None
      email_allow_regex: compiled regex or None
      name_singular_rules: [(compiled_regex, replacement_bytes), ...]
      name_catchall_replace: string or None
      name_allow_regex: compiled regex or None
    """
    blob_replacements = []
    message_replacements = []
    path_removals = []
    path_renames = []
    email_singular_rules = []
    email_catchall_replace = None
    email_allow_regex = None
    name_singular_rules = []
    name_catchall_replace = None
    name_allow_regex = None

    for entry in config.get("patterns", []):
        action = entry.get("action", "report")
        if action not in ("replace", "remove"):
            continue
        pattern = entry["pattern"]
        if action == "remove":
            replace_with = ""
        else:
            replace_with = entry.get("replace-with", "***REDACTED***")

        flags = re.IGNORECASE if pattern.startswith("(?i)") else 0
        search_pattern = pattern[4:] if pattern.startswith("(?i)") else pattern
        compiled = re.compile(search_pattern.encode(), flags)
        replacement = replace_with.encode()
        blob_replacements.append((compiled, replacement))
        message_replacements.append((compiled, replacement))

    for entry in config.get("paths", []):
        action = entry.get("action", "report")
        if action == "remove":
            path_removals.append(entry["pattern"])
        elif action == "replace" and "replace-with" in entry:
            path_renames.append((entry["pattern"], entry["replace-with"]))

    # Singular git-author-email entries (like patterns, for specific emails)
    for entry in config.get("git-author-email", []):
        action = entry.get("action", "report")
        if action not in ("replace", "remove"):
            continue
        pattern = entry.get("email", entry.get("pattern", ""))
        if action == "remove":
            replace_with = ""
        else:
            replace_with = entry.get("replace-with", "REDACTED")
        flags = re.IGNORECASE if pattern.startswith("(?i)") else 0
        search_pattern = pattern[4:] if pattern.startswith("(?i)") else pattern
        compiled = re.compile(search_pattern.encode(), flags)
        email_singular_rules.append((compiled, replace_with.encode()))

    # Plural git-author-emails: catch-all for non-allowlisted emails
    email_plural = config.get("git-author-emails", {})
    if email_plural.get("action") in ("replace", "remove"):
        email_catchall_replace = email_plural.get(
            "replace-with", "REDACTED@users.noreply.github.com"
        )
        entries = email_plural.get("entries", [])
        patterns = [e["email"] if isinstance(e, dict) else e for e in entries]
        if patterns:
            email_allow_regex = re.compile(
                "|".join(f"^({p})$" for p in patterns).encode()
            )

    # Singular git-author-name entries
    for entry in config.get("git-author-name", []):
        action = entry.get("action", "report")
        if action not in ("replace", "remove"):
            continue
        pattern = entry.get("name", entry.get("pattern", ""))
        if action == "remove":
            replace_with = ""
        else:
            replace_with = entry.get("replace-with", "REDACTED")
        flags = re.IGNORECASE if pattern.startswith("(?i)") else 0
        search_pattern = pattern[4:] if pattern.startswith("(?i)") else pattern
        compiled = re.compile(search_pattern.encode(), flags)
        name_singular_rules.append((compiled, replace_with.encode()))

    # Plural git-author-names: catch-all for non-allowlisted names
    name_plural = config.get("git-author-names", {})
    if name_plural.get("action") in ("replace", "remove"):
        name_catchall_replace = name_plural.get("replace-with", "REDACTED")
        entries = name_plural.get("entries", [])
        patterns = [e["name"] if isinstance(e, dict) else e for e in entries]
        if patterns:
            name_allow_regex = re.compile(
                "|".join(f"^({p})$" for p in patterns).encode()
            )

    return {
        "blob_replacements": blob_replacements,
        "message_replacements": message_replacements,
        "path_removals": path_removals,
        "path_renames": path_renames,
        "email_singular_rules": email_singular_rules,
        "email_catchall_replace": email_catchall_replace,
        "email_allow_regex": email_allow_regex,
        "name_singular_rules": name_singular_rules,
        "name_catchall_replace": name_catchall_replace,
        "name_allow_regex": name_allow_regex,
    }


def preview_rewrite(rules, config):
    """Print a preview of what would be rewritten."""
    print()
    print("=== Rewrite preview (dry run) ===")
    print()

    blob = rules["blob_replacements"]
    if blob:
        print("Text replacements in file contents:")
        for regex, replacement in blob:
            pattern = regex.pattern.decode("utf-8", errors="replace")
            repl = replacement.decode("utf-8", errors="replace") or "(empty string)"
            print(f"  {pattern}  =>  {repl}")
        print()

    msg = rules["message_replacements"]
    if msg:
        print("Text replacements in commit messages:")
        for regex, replacement in msg:
            pattern = regex.pattern.decode("utf-8", errors="replace")
            repl = replacement.decode("utf-8", errors="replace") or "(empty string)"
            print(f"  {pattern}  =>  {repl}")
        print()

    path_rm = rules["path_removals"]
    if path_rm:
        print("Paths to remove from history:")
        for p in path_rm:
            print(f"  {p}")
        print()

    path_rn = rules["path_renames"]
    if path_rn:
        print("Paths to rename in history:")
        for old, new in path_rn:
            print(f"  {old}  =>  {new}")
        print()

    if rules["email_singular_rules"]:
        print("Singular email replacements:")
        for regex, replacement in rules["email_singular_rules"]:
            pattern = regex.pattern.decode("utf-8", errors="replace")
            repl = replacement.decode("utf-8", errors="replace") or "(empty string)"
            print(f"  {pattern}  =>  {repl}")
        print()

    if rules["email_catchall_replace"]:
        print(
            f"Non-allowlisted emails will be replaced with: {rules['email_catchall_replace']}"
        )
        print()

    if rules["name_singular_rules"]:
        print("Singular name replacements:")
        for regex, replacement in rules["name_singular_rules"]:
            pattern = regex.pattern.decode("utf-8", errors="replace")
            repl = replacement.decode("utf-8", errors="replace") or "(empty string)"
            print(f"  {pattern}  =>  {repl}")
        print()

    if rules["name_catchall_replace"]:
        print(
            f"Non-allowlisted names will be replaced with: {rules['name_catchall_replace']}"
        )
        print()

    if not any(
        [
            blob,
            msg,
            path_rm,
            path_rn,
            rules["email_singular_rules"],
            rules["email_catchall_replace"],
            rules["name_singular_rules"],
            rules["name_catchall_replace"],
        ]
    ):
        print("No rewrite actions found in config.")


def do_rewrite(repo_path, rules, dry_run=False):
    """Rewrite git history using git-filter-repo based on collected rules."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "git_filter_repo", str(SCRIPT_DIR / "git_filter_repo.py")
    )
    fr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fr)

    # Build FilteringOptions args
    # MUST pass both --source AND --target, otherwise git-filter-repo
    # defaults --target to cwd, rewriting the wrong repo.
    args_list = [
        "--source",
        str(repo_path),
        "--target",
        str(repo_path),
        "--force",
    ]

    if dry_run:
        args_list.append("--dry-run")

    # Path removals: --path <pattern> --invert-paths
    if rules["path_removals"]:
        for pattern in rules["path_removals"]:
            args_list.extend(["--path", pattern])
        args_list.append("--invert-paths")

    # Path renames
    for old, new in rules["path_renames"]:
        args_list.extend(["--path-rename", f"{old}:{new}"])

    args = fr.FilteringOptions.parse_args(args_list)

    # Create callbacks
    blob_rules = rules["blob_replacements"]
    msg_rules = rules["message_replacements"]
    email_singular = rules["email_singular_rules"]
    email_catchall = rules["email_catchall_replace"]
    email_allow = rules["email_allow_regex"]
    name_singular = rules["name_singular_rules"]
    name_catchall = rules["name_catchall_replace"]
    name_allow = rules["name_allow_regex"]

    def blob_callback(blob, callback_data):
        for regex, replacement in blob_rules:
            blob.data = regex.sub(replacement, blob.data)

    def message_callback(message):
        for regex, replacement in msg_rules:
            message = regex.sub(replacement, message)
        return message

    def email_callback(email):
        # Check singular rules first (specific email -> specific replacement)
        for regex, replacement in email_singular:
            if regex.search(email):
                return replacement
        # Then catch-all: if not allowlisted, use global replacement
        if email_catchall and email_allow and not email_allow.match(email):
            return email_catchall.encode()
        return email

    def name_callback(name):
        # Check singular rules first
        for regex, replacement in name_singular:
            if regex.search(name):
                return replacement
        # Then catch-all: if not allowlisted, use global replacement
        if name_catchall and name_allow and not name_allow.match(name):
            return name_catchall.encode()
        return name

    has_email_rules = bool(email_singular) or (email_catchall and email_allow)
    has_name_rules = bool(name_singular) or (name_catchall and name_allow)

    repo_filter = fr.RepoFilter(
        args,
        blob_callback=blob_callback if blob_rules else None,
        message_callback=message_callback if msg_rules else None,
        email_callback=email_callback if has_email_rules else None,
        name_callback=name_callback if has_name_rules else None,
    )
    repo_filter.run()


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

    # Validate mutually exclusive flags
    if args.pipeline and args.rewrite:
        print(
            "ERROR: --pipeline and --rewrite are mutually exclusive.", file=sys.stderr
        )
        print(
            "  Use --pipeline for detection (CI/CD), --rewrite for history rewriting.",
            file=sys.stderr,
        )
        sys.exit(2)
    if args.pipeline and args.preview:
        print(
            "ERROR: --pipeline and --preview are mutually exclusive.", file=sys.stderr
        )
        sys.exit(2)
    if args.preview and args.rewrite:
        print("ERROR: --preview and --rewrite are mutually exclusive.", file=sys.stderr)
        print(
            "  Use --preview to see what would change, --rewrite to actually change it.",
            file=sys.stderr,
        )
        sys.exit(2)

    # Validate repo
    if not (repo_path / ".git").is_dir():
        print(f"ERROR: {repo_path} is not a git repository", file=sys.stderr)
        sys.exit(2)

    # Safety check: refuse to rewrite the git-redact repo itself
    if args.rewrite and repo_path == SCRIPT_DIR:
        print(
            "ERROR: Refusing to rewrite the git-redact repo itself.",
            file=sys.stderr,
        )
        print(
            "If you really want to do this, run from a different directory",
            file=sys.stderr,
        )
        print("and specify the target repo path explicitly.", file=sys.stderr)
        sys.exit(2)

    # Find and load config
    config_path = find_config(args.config, repo_path)
    config = load_config(config_path, no_builtin=args.no_builtin)

    # Set up output: in pipeline mode, human-readable goes to stderr
    log_buffer = io.StringIO()
    original_stdout = sys.stdout
    if args.pipeline:
        sys.stdout = TeeWriter(sys.stderr, log_buffer)
    else:
        sys.stdout = TeeWriter(original_stdout, log_buffer)

    if config_path:
        print(f"Using config: {config_path}")
    else:
        print("No user config found \u2014 using built-in patterns only")

    print(f"Auditing git history in: {repo_path}")
    print("Searching all commits across all refs...")
    print()

    all_findings = []

    # Fetch diff once for all pattern and entropy checks
    diff_lines = get_diff_lines(repo_path)
    if args.no_binary:
        diff_lines = filter_binary_sections(diff_lines)
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

    # ── Git author emails ──
    email_singular = config.get("git-author-email", [])
    email_plural = config.get("git-author-emails", {"entries": []})
    if email_singular or email_plural.get("entries") or email_plural.get("action"):
        all_findings.extend(
            check_author_emails(repo_path, email_singular, email_plural)
        )

    # ── Git author names ──
    name_singular = config.get("git-author-name", [])
    name_plural = config.get("git-author-names", {"entries": []})
    if name_singular or name_plural.get("entries") or name_plural.get("action"):
        all_findings.extend(check_author_names(repo_path, name_singular, name_plural))

    # ── History rewriting ──
    replace_remove = [f for f in all_findings if f["action"] in ("replace", "remove")]
    rules = collect_rewrite_rules(config)
    has_rewrite_rules = any(
        [
            rules["blob_replacements"],
            rules["message_replacements"],
            rules["path_removals"],
            rules["path_renames"],
            rules["email_singular_rules"],
            rules["email_catchall_replace"],
            rules["name_singular_rules"],
            rules["name_catchall_replace"],
        ]
    )

    if args.rewrite and has_rewrite_rules:
        # Actually rewrite history — require explicit confirmation
        print()
        print("=== WARNING: History rewriting ===")
        print("This will IRREVERSIBLY rewrite git history in:")
        print(f"  {repo_path}")
        print("All commit hashes will change. Force-push to update remotes.")
        print()
        if not args.y:
            answer = input("Type 'yes' to confirm: ")
            if answer.strip().lower() != "yes":
                print("Aborted. No changes were made.")
                sys.exit(0)

        # Countdown before proceeding
        import time

        for i in range(5, 0, -1):
            print(f"\rRewriting in {i}...  (Ctrl+C to abort)", end="", flush=True)
            time.sleep(1)
        print("\rStarting rewrite...                    ")

        try:
            do_rewrite(repo_path, rules, dry_run=False)
            print("History rewrite complete.")
        except Exception as e:
            print(f"ERROR: History rewrite failed: {e}", file=sys.stderr)
            sys.exit(2)
    elif args.preview and has_rewrite_rules:
        # Show preview of what would be rewritten
        preview_rewrite(rules, config)
    elif replace_remove and not args.rewrite and not args.preview:
        # Just report that these actions exist but aren't being executed
        print()
        print("NOTE: The following entries have replace/remove actions.")
        print("Use --preview to see what would change, or --rewrite to apply changes.")
        for f in replace_remove:
            print(f"  - {f['label']} ({f['action'].upper()})")
    elif has_rewrite_rules and not args.rewrite and not args.preview:
        print()
        print("NOTE: Config has replace/remove actions defined.")
        print("Use --preview to see what would change, or --rewrite to apply changes.")

    # ── Summary ──
    failures = [f for f in all_findings if f["action"] == "report"]
    if not failures:
        result = "PASS: No personal data found in git history"
    else:
        result = "FAIL: Personal data found in git history (see above)"

    # Only show PASS/FAIL summary for audit and rewrite, not preview
    if not args.preview:
        print()
        print("=" * 42)
        print(result)

    # ── Write report if requested ──
    # Restore stdout before writing report/pipeline so output goes to
    # the real terminal, not into the capture buffer.
    sys.stdout = original_stdout
    if args.pipeline:
        from datetime import datetime, timezone

        pipeline_data = {
            "repository": str(repo_path),
            "config": str(config_path) if config_path else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": "PASS" if not failures else "FAIL",
            "findings": [
                {
                    "label": f["label"],
                    "action": f["action"],
                    "count": f["count"],
                    **({"unique": f["unique"]} if "unique" in f else {}),
                }
                for f in all_findings
            ],
            "stats": {
                "total": len(all_findings),
                "report": len([f for f in all_findings if f["action"] == "report"]),
                "warn": len([f for f in all_findings if f["action"] == "warn"]),
                "replace": len([f for f in all_findings if f["action"] == "replace"]),
                "remove": len([f for f in all_findings if f["action"] == "remove"]),
            },
        }
        print(json.dumps(pipeline_data, indent=2))

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
            unique_str = f", {f['unique']} unique" if "unique" in f else ""
            lines.append(
                f"  [{action_label(f['action'])}] {f['label']} ({f['count']}{unique_str})"
            )
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
