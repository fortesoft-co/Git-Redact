# git-redact

Audit and scrub git repositories for personal data that shouldn't be in a
public repo — paths, names, emails, locations, secrets, API keys, and more.
Fully configurable via a TOML config file so you never need to edit the script
itself.

## Quick start

```sh
# 1. Copy the example config and customise it
cp git-redact.conf.example.toml git-redact.conf.toml

# 2. Run the audit against a repo
python3 git-redact.py /path/to/repo

# Or run against the current directory
cd /path/to/repo
python3 /path/to/git-redact.py
```

**No external dependencies** — Python 3.11+ (for built-in TOML support) and git
are all you need. `git-filter-repo` is vendored for future history-rewriting
support.

## Configuration

The config file is TOML with three sections:

```toml
# Paths — files/directories to check in git history
[[paths]]
label = "secrets/ directory (should be removed)"
pattern = "secrets/"
action = "remove"

# Patterns — text/regex to search in git diff output
[[patterns]]
label = "Email johnd@gmail.com"
pattern = "johnd@gmail.com"
action = "report"

[[patterns]]
label = "AWS Access Key IDs"
pattern = "AKIA[0-9A-Z]{16}"
action = "report"

[[patterns]]
label = "Private IPv4 addresses (may be acceptable)"
pattern = '(192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+)'
action = "warn"

# Allow-emails — git author emails considered safe (regex)
[allow-emails]
action = "report"
# replace-with = "REDACTED@users.noreply.github.com"

[[allow-emails.entries]]
email = '123456789\+johndoe@users\.noreply\.github\.com'
```

### Sections

| Section | Checks | Replace semantics |
|---------|--------|-------------------|
| `paths` | Did this file/dir exist in history? | Delete or rename the path |
| `patterns` | Does this text appear in diffs? | Swap matched text |
| `allow-emails` | Is this email in the allow-list? | Rewrite non-matching emails |

### Actions

| Action | Behavior |
|--------|----------|
| `report` | Find and report, cause exit 1 if found (default) |
| `warn` | Find and report, but don't cause exit 1 |
| `replace` | Find and replace with `replace-with` value (future) |
| `remove` | Delete entirely — paths only (future) |

> **Note:** `replace` and `remove` actions are reported but not yet executed.
> History rewriting via `git-filter-repo` will be added in a future release.
> Use `--dry-run` to preview what would change.

### TOML tips

Use single-quoted strings for regex patterns to avoid double-escaping:

```toml
# Single-quoted: backslashes are literal (cleaner for regex)
pattern = '(192\.168\.[0-9]+\.[0-9]+)'

# Double-quoted: backslashes must be escaped
pattern = "(192\\.168\\.[0-9]+\\.[0-9]+)"
```

### Config file resolution

The script looks for a config file in this order:

1. `--config /path/to/config.toml` CLI flag
2. `GIT_REDACT_CONFIG` environment variable
3. `<repo>/git-redact.conf.toml`
4. `<script-dir>/git-redact.conf.toml`

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No personal data found |
| 1 | Personal data found — see report |
| 2 | Error (not a git repo, missing config, etc.) |

## Vendored tools

| Tool | License | Source |
|------|---------|--------|
| git-filter-repo | MIT | [newren/git-filter-repo](https://github.com/newren/git-filter-repo) |

## Requirements

- Python 3.11+ (for built-in `tomllib`)
- git

## License

MIT