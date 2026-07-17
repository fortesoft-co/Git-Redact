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
| `replace` | Find and replace with `replace-with` value (future) |
| `remove` | Delete entirely — paths only (future) |

> **Note:** `replace` and `remove` actions are reported but not yet executed.
> History rewriting via `git-filter-repo` will be added in a future release.
> Use `--dry-run` to preview what would change.

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
