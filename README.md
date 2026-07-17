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

# Skip built-ins if you only want your own patterns
python3 git-redact.py --no-builtin /path/to/repo

# Skip binary files (avoids noise from images, binaries, etc.)
python3 git-redact.py --no-binary /path/to/repo

# Output JSON for CI/CD pipelines
python3 git-redact.py --pipeline /path/to/repo

# Preview what rewrite would change (safe, no modifications)
python3 git-redact.py --preview /path/to/repo

# Rewrite history (with confirmation and 5s countdown)
python3 git-redact.py --rewrite /path/to/repo
```

**No external dependencies** — Python 3.11+ (for built-in TOML support) and git
are all you need. `git-filter-repo` is vendored for future history-rewriting
support.

Built-in patterns (private keys, API tokens, credentials) are loaded
automatically. You only need a config file for personal patterns.

## Built-in patterns

`git-redact.conf.builtin.toml` ships with patterns for well-known secrets
that are checked by default. They merge with your config and can be
overridden or skipped entirely:

- **Sensitive file paths** — SSH keys, PEM/PKCS12/JKS files, `.ssh/`, `.aws/`,
  `.gnupg/`, `.env`, `.netrc`, `.pypirc`, `.htpasswd`, `secrets/`, and more
- **Private keys and certificates** — PEM, PGP, PKCS12, SSH, Age
- **Hardcoded secrets** — password/secret/API key assignments, auth headers,
  basic auth in URLs, database connection strings
- **Cloud provider keys** — AWS, GCP, Azure
- **GitHub/GitLab tokens** — PATs, OAuth, App, Deploy, Runner tokens
- **SaaS tokens** — Slack, Stripe, SendGrid, Twilio, Mailgun, DigitalOcean,
  Heroku, Shopify, Docker
- **JWTs** — JSON Web Token detection

Use `--no-builtin` to skip them, or override specific entries by label (see below).

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
| `replace` | Find and replace with `replace-with` value |
| `remove` | Delete text or remove paths entirely |

### History rewriting

`replace` and `remove` actions can rewrite git history using the vendored
`git-filter-repo`. This is **irreversible** — all commit hashes change.

```sh
# Preview what would be rewritten (safe, no changes made)
python3 git-redact.py --preview /path/to/repo

# Rewrite history (will prompt for confirmation + 5s countdown)
python3 git-redact.py --rewrite /path/to/repo

# Skip confirmation (for scripts — use with extreme caution)
python3 git-redact.py --rewrite -y /path/to/repo
```

**Safety guards:**
- `--rewrite` requires typing `yes` at a confirmation prompt, then waits 5 seconds
- `-y` skips the prompt (for automated use)
- `--preview` shows what would change without modifying anything
- `--pipeline` is mutually exclusive with `--rewrite` and `--preview` (detection only)
- Always specify the repo path explicitly to avoid accidental rewrites
- The tool refuses to rewrite its own repository

Pattern `replace` replaces matched text with `replace-with` (default:
`***REDACTED***`). Pattern `remove` deletes matched text entirely. Path
`remove` deletes files from history. Path `replace` renames paths using
`replace-with`. Email `replace` rewrites non-allowlisted emails.

> **Note:** The audit still runs before rewriting. Only entries with `replace`
> or `remove` actions are rewritten. `report` and `warn` entries are never
> rewritten.

### Output format

Pattern matches are deduplicated — identical lines are grouped with a count
rather than printed repeatedly:

```
=== Password 'hunter2' (2 unique, 47 total) [FAIL] ===
  [x25] +password = "hunter2"
  [x22] +db_password = "hunter2"
```

The first number is unique matches, the second is total occurrences across
all commits.

### Overriding built-in patterns

If a pattern or path in your config has the same `label` as a built-in one,
your entry **replaces** the builtin. This lets you change the action without
editing the shipped file:

```toml
# Downgrade the PKCS12 builtin from 'warn' to 'report'
[[patterns]]
label = "PKCS12 / PFX certificate files"
pattern = '\.p12|\.pfx'
action = "report"
```

Overrides are printed to stderr so you can see what's being replaced:

```
  Override: [patterns] 'PKCS12 / PFX certificate files' replaced by user config
```

### Config file resolution

The script looks for a config file in this order:

1. `--config /path/to/config.toml` CLI flag
2. `GIT_REDACT_CONFIG` environment variable
3. `<repo>/git-redact.conf.toml`
4. `<script-dir>/git-redact.conf.toml`

If no config file is found, built-in patterns still run. You only need a
config file for personal data (names, emails, timezones, etc.).

To skip built-in patterns entirely and only use your config:

```sh
python3 git-redact.py --no-builtin /path/to/repo
```

To skip binary files in diff output (reduces noise from images, archives, etc.):

```sh
python3 git-redact.py --no-binary /path/to/repo
```

### Pipeline mode

For CI/CD integration, use `--pipeline` to output findings as JSON to stdout.
Human-readable output goes to stderr, so only JSON appears on stdout.
`--pipeline` is for detection only — it cannot be combined with `--rewrite` or `--preview`.

```sh
python3 git-redact.py --pipeline /path/to/repo
```

Output format:

```json
{
  "repository": "/path/to/repo",
  "config": "/path/to/git-redact.conf.toml",
  "timestamp": "2024-01-15T12:34:56+00:00",
  "result": "FAIL",
  "findings": [
    {"label": "SSH private key references", "action": "report", "count": 5, "unique": 3},
    {"label": "Email addresses", "action": "warn", "count": 12}
  ],
  "stats": {
    "total": 2,
    "report": 1,
    "warn": 1,
    "replace": 0,
    "remove": 0
  }
}
```

The `unique` field is included when available (pattern and commit message findings).
Exit codes remain the same: 0 = pass, 1 = fail, 2 = error.

### TOML tips

Use single-quoted strings for regex patterns to avoid double-escaping:

```toml
# Single-quoted: backslashes are literal (cleaner for regex)
pattern = '(192\.168\.[0-9]+\.[0-9]+)'

# Double-quoted: backslashes must be escaped
pattern = "(192\\.168\\.[0-9]+\\.[0-9]+)"
```

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
