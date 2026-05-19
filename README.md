# GistSafe

Encrypted secret management for developers. Store environment variables securely in private GitHub Gists.

## Features

- Strong encryption via PBKDF2HMAC-SHA256 + Fernet
- Private GitHub Gists as storage — no infrastructure to manage
- Per-project, per-environment secret organization
- Inject secrets as environment variables into any command
- Optional key obfuscation (encrypts variable names too)
- Password hints for recovery
- Local caching for fast lookups

## Installation

```bash
pip install gistsafe
```

Or with pipx (recommended for CLI tools):

```bash
pipx install gistsafe
```

From source:

```bash
git clone https://github.com/leoduff/gistsafe.git
cd gistsafe
pip install .
```

### Setup

Create a `.env` file in your project directory, or set the environment variable:

```bash
export GITHUB_TOKEN=ghp_yourtokenhere
```

You need a [GitHub personal access token](https://github.com/settings/tokens) with the `gist` scope.

**Requirements**: Python 3.10+

## Quick Start

```bash
# Create secrets for a project
gistsafe create --project myapp --environment dev
# → prompts for key/value pairs and an encryption password

# View secrets
gistsafe get --project myapp --environment dev

# Run a command with secrets injected as env vars
gistsafe inject --project myapp --environment dev -- npm start

# List all projects
gistsafe list
```

## Usage

### Creating Secrets

```bash
gistsafe create --project myapp --environment dev
```

Options:
- `--password-hint "Office wifi password"` — hint shown before password prompt
- `--obfuscate-keys` — encrypts key names as well as values

With obfuscation enabled, `DATABASE_URL` in storage becomes `gAAAAABk7X...`. Original names are restored on retrieval.

### Updating Secrets

```bash
gistsafe update --project myapp --environment dev
```

Shows current secrets first, then prompts for new values. Unchanged secrets are preserved.

### Retrieving Secrets

```bash
gistsafe get --project myapp --environment dev
```

If a password hint was set, it displays before the password prompt.

### Injecting Secrets into Commands

```bash
gistsafe inject --project myapp --environment prod -- npm start
gistsafe inject --project myapp -- npm test
gistsafe inject --project myapp -- printenv API_KEY
```

The `inject` command decrypts secrets, uppercases the keys, sets them as environment variables, and runs your command. If `--environment` is omitted, it uses `NODE_ENV` (defaulting to `development`).

### Listing Projects

```bash
gistsafe list
```

Shows all projects, their environments, and gist URLs in a table.

## Architecture

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐
│  CLI     │────▶│  GistSafe    │────▶│  GitHub API │
│ (Click)  │     │  (manager)   │     │  (PyGithub) │
└──────────┘     └──────┬───────┘     └─────────────┘
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
        ┌─────────┐ ┌───────┐ ┌─────────┐
        │ crypto  │ │ cache │ │ display │
        │(Fernet) │ │ (JSON)│ │ (Rich)  │
        └─────────┘ └───────┘ └─────────┘
```

Secrets are encrypted client-side with your password before touching the network. GitHub never sees plaintext.

## Caching

GistSafe maintains a local index at `~/.gistsafe/cache.json` to avoid hammering the GitHub API. The cache:

- Stores project names, environments, and gist IDs (never secrets)
- Auto-refreshes in the background when stale (>1 hour)
- Updates immediately on create/update operations
- Falls back to direct API search on cache miss

## Security

### What's Protected

- All secrets are encrypted with PBKDF2HMAC-SHA256 (100,000 iterations) + Fernet before storage
- Encryption password never leaves your machine
- Gists are created as private by default
- Optional key obfuscation hides variable names in storage

### Limitations

GistSafe is designed for development and personal projects. It is **not** suitable for:

- Production environments
- Regulated industries (finance, healthcare)
- Applications requiring SOC2, HIPAA, or PCI compliance

For production use, consider HashiCorp Vault, AWS Secrets Manager, Doppler, or Infisical.

### Best Practices

- Use strong, unique passwords per project
- Rotate GitHub tokens regularly
- Enable 2FA on your GitHub account
- Use key obfuscation for sensitive projects
- Never include the actual password in hints

## Development

```bash
git clone https://github.com/leoduff/gistsafe.git
cd gistsafe
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run tests:

```bash
# Test crypto roundtrip
python -c "from gistsafe.crypto import encrypt_value, decrypt_value; import os; s=os.urandom(16); v,s2=encrypt_value('test','pw',s); assert decrypt_value(v,'pw',s2)=='test'; print('OK')"
```

## License

MIT
