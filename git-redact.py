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
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def parse_args():
    parser = argparse.ArgumentParser(
        prog="git-redact",
        description="Audit git repositories for personal data.",
    )
    parser.add_argument("repo", nargs="?", default=os.getcwd(),
                        help="Path to the git repo (default: current directory)")
    parser.add_argument("-c", "--config", default=None,
                        help="Path to config file")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="Show what would be replaced/removed without doing it")
    return parser.parse_args()


def find_config(args_config, repo_path):
    """Resolve config file path."""
    if args_config:
        config = Path(args_config)
        if not config.is_file():
            print(f"ERROR: Config file not found: {config}", file=sys.stderr)
            sys.exit(2)
        return config

    # Search in order: env var, repo root, script dir
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

    print("ERROR: Config file not found. Set GIT_REDACT_CONFIG, pass --config, or",
          file=sys.stderr)
    print("       place git-redact.conf.toml in the repo root or next to the script.",
          file=sys.stderr)
    sys.exit(2)


def load_config(config_path):
    """Load and validate TOML config."""
    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    # Validate required sections exist (can be empty)
    for section in ("paths", "patterns"):
        if section not in config:
            config[section] = []
    if "allow-emails" not in config:
        config["allow-emails"] = {"entries": []}

    return config


def git_cmd(repo_path, *args):
    """Run a git command and return stdout."""
    result = subprocess.run(
        ["git", "-C", str(repo_path)] + list(args),
        capture_output=True, text=True, errors="replace",
    )
    return result.stdout


def action_label(action):
    """Return display label for an action."""
    return {"report": "FAIL", "warn": "WARN", "replace": "REPLACE", "remove": "REMOVE"}.get(action, action.upper())


def check_paths(repo_path, entries):
    """Check for sensitive paths in git history."""
    findings = []
    for entry in entries:
        label = entry.get("label", entry["pattern"])
        pattern = entry["pattern"]
        action = entry.get("action", "report")

        output = git_cmd(repo_path, "log", "--all", "--name-only", "--pretty=format:", "--", pattern)
        files = [f for f in output.splitlines() if f.strip()]
        count = len(set(files))  # unique files

        if count > 0:
            print()
            print(f"=== {label} ({count} unique file entries) [{action_label(action)}] ===")
            for f in sorted(set(files))[:30]:
                print(f)
            findings.append({"label": label, "action": action, "count": count})

    return findings


def check_patterns(repo_path, entries):
    """Check for text patterns in git history."""
    findings = []
    for entry in entries:
        label = entry.get("label", entry["pattern"])
        pattern = entry["pattern"]
        action = entry.get("action", "report")

        # Use grep -E for extended regex support
        result = subprocess.run(
            ["git", "-C", str(repo_path), "log", "--all", "-p"],
            capture_output=True, text=True, errors="replace",
        )
        matches = []
        for line in result.stdout.splitlines():
            if re.search(pattern, line):
                matches.append(line)

        count = len(matches)
        if count > 0:
            print()
            print(f"=== {label} ({count} matches) [{action_label(action)}] ===")
            for m in matches[:20]:
                print(m)
            findings.append({"label": label, "action": action, "count": count})

    return findings


def check_patterns_fast(repo_path, entries):
    """Check for text patterns in git history using grep for speed."""
    findings = []
    for entry in entries:
        label = entry.get("label", entry["pattern"])
        pattern = entry["pattern"]
        action = entry.get("action", "report")

        # Count matches
        count_result = subprocess.run(
            ["git", "-C", str(repo_path), "log", "--all", "-p"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace",
        )
        count = 0
        matching_lines = []
        for line in count_result.stdout.splitlines():
            if re.search(pattern, line):
                count += 1
                if len(matching_lines) < 20:
                    matching_lines.append(line)

        if count > 0:
            print()
            print(f"=== {label} ({count} matches) [{action_label(action)}] ===")
            for m in matching_lines:
                print(m)
            findings.append({"label": label, "action": action, "count": count})

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
        return [{"label": "Non-allowlisted emails", "action": action,
                 "count": len(personal_emails)}]

    return []


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

    # ── Paths ──
    path_entries = config.get("paths", [])
    all_findings.extend(check_paths(repo_path, path_entries))

    # ── Patterns ──
    pattern_entries = config.get("patterns", [])
    all_findings.extend(check_patterns_fast(repo_path, pattern_entries))

    # ── Emails ──
    allow_config = config.get("allow-emails", {"entries": []})
    all_findings.extend(check_emails(repo_path, allow_config))

    # ── Future: replace/remove actions ──
    replace_remove = [f for f in all_findings if f["action"] in ("replace", "remove")]
    if replace_remove and not args.dry_run:
        print()
        print("NOTE: The following entries have replace/remove actions but history rewriting")
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
        print("PASS: No personal data found in git history")
        sys.exit(0)
    else:
        print("FAIL: Personal data found in git history (see above)")
        sys.exit(1)


if __name__ == "__main__":
    main()
