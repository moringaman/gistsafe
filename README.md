# GistSafe

GistSafe is a secure secret management tool that uses GitHub Gists as a backend for storing encrypted secrets. It provides a simple CLI interface for managing secrets across different projects and environments.

## Features

- 🔐 Strong encryption using PBKDF2HMAC with SHA256
- 🌐 Uses private GitHub Gists as storage
- 🔄 Environment-based secret management
- 💉 Secret injection into runtime environment
- 🏷️ Optional password hints for secret recovery
- 📝 Support for multiple projects and environments
- 🎭 Optional key obfuscation for enhanced security

## Installation

### Quick Install (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/yourusername/gistsafe.git
cd gistsafe
```

2. Run the installation script:
```bash
./install.sh
```

3. Follow the on-screen instructions to:
   - Add your GitHub token to the `.env` file
   - Source your shell configuration file
   - Test the installation with `gistsafe --help`

The installation script will:
- Create a Python virtual environment
- Install all dependencies
- Add GistSafe to your PATH
- Create a `.env` file template
- Support both bash and zsh shells

### Manual Installation

If you prefer to install manually:

1. Clone the repository:
```bash
git clone https://github.com/yourusername/gistsafe.git
cd gistsafe
```

2. Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your GitHub token:
```bash
echo "GITHUB_TOKEN=your_github_token_here" > .env
```

5. Add the GistSafe directory to your PATH or create a symlink:
```bash
# Option 1: Add to PATH in your shell config (.bashrc, .zshrc, etc.)
export PATH="/path/to/gistsafe/bin:$PATH"

# Option 2: Create a symlink
ln -s /path/to/gistsafe/gistsafe.py /usr/local/bin/gistsafe
```

## Usage

### Creating Secrets

Create new secrets for a project and environment:

```bash
gistsafe create --project your-project --environment dev
```

Optional: Add a password hint to help remember your encryption password:
```bash
gistsafe create --project your-project --environment dev --password-hint "Office wifi password"
```

For enhanced security, you can obfuscate the secret keys as well as the values:
```bash
gistsafe create --project your-project --environment dev --obfuscate-keys
```

This means that even the names of your environment variables will be encrypted in storage. For example:
- `DATABASE_URL` becomes something like `gAAAAABk7X...` in storage
- `API_KEY` becomes something like `gAAAAABk7Y...` in storage

The original names are automatically restored when you retrieve or inject the secrets.

### Updating Secrets

Update existing secrets:

```bash
gistsafe update --project your-project --environment dev
```

You can also update or add a password hint during update:
```bash
gistsafe update --project your-project --environment dev --password-hint "New hint"
```

### Retrieving Secrets

View secrets for a project and environment:

```bash
gistsafe get --project your-project --environment dev
```

If a password hint was set, it will be displayed before the password prompt.

### Injecting Secrets into Runtime Environment

Run commands with secrets injected as environment variables:

```bash
# Using explicit environment
gistsafe inject --project your-project npm run start

# Using NODE_ENV to determine environment
export NODE_ENV=production
gistsafe inject --project your-project npm run start
```

The inject command will:
1. Load secrets from the specified project and environment
2. Convert secret keys to uppercase
3. Inject them as environment variables
4. Display which variables were injected (with masked values)
5. Run your specified command

Example:
```bash
# If you have a secret named "api_key"
# It will be available in your application as:
process.env.API_KEY
```

## Security Best Practices

1. **Password Management**:
   - Use strong, unique passwords for each project
   - Store passwords securely (e.g., in a password manager)
   - Use meaningful but secure password hints
   - Never include the actual password in the hint

2. **Environment Variables**:
   - Keep your GitHub token secure
   - Don't commit the `.env` file
   - Regularly rotate your GitHub token
   - Use key obfuscation for sensitive projects

3. **Secret Access**:
   - Use different passwords for different environments
   - Limit access to production secrets
   - Regularly audit your gists
   - Enable key obfuscation for production environments

## Command Reference

### List Command
```bash
gistsafe list
```
Lists all available GistSafe projects and their environments in a table format, showing:
- Project names
- Available environments for each project
- Gist URLs for easy access

### Create Command
```bash
gistsafe create --project PROJECT --environment ENV [--password-hint HINT] [--obfuscate-keys]
```
- `PROJECT`: Your project name
- `ENV`: Environment (e.g., dev, prod)
- `--password-hint`: Optional hint to help remember the password
- `--obfuscate-keys`: Encrypt secret keys as well as values

### Update Command
```bash
gistsafe update --project PROJECT --environment ENV [--password-hint HINT]
```

## Caching System

GistSafe includes an intelligent caching system to improve performance and reduce API calls to GitHub. The cache system:

- Stores project and environment information locally at `~/.gistsafe/cache.json`
- Updates asynchronously in the background without blocking operations
- Auto-refreshes when:
  - Cache is older than 1 hour
  - Cache lookup fails
  - New secrets are created or updated
- Provides thread-safe operations for concurrent access
- Falls back to direct GitHub API calls if cache is unavailable

The cache maintains:
- Project names and environments
- Gist IDs and URLs
- File names and metadata

No sensitive information or secrets are ever stored in the cache.

### Cache Benefits

- Faster project listing and secret lookups
- Reduced GitHub API usage
- Better performance for frequently accessed projects
- Non-blocking operations for improved user experience

## Security Disclaimer

⚠️ **Important Security Notice**

GistSafe is designed for development environments and personal projects. While we implement strong encryption practices and security measures, please note the following:

### Limitations and Risks
- GitHub Gists are used as the storage backend, making your secrets' availability dependent on GitHub's service
- Access to encrypted secrets relies on GitHub authentication and personal access tokens
- No built-in audit logging or compliance monitoring
- Limited access control (based on GitHub's permissions)
- No automatic secret rotation or expiration
- No enterprise-grade backup or disaster recovery features

### Not Recommended For
- Production environments
- Enterprise applications
- Regulated industries (finance, healthcare, etc.)
- Critical infrastructure
- Applications requiring compliance (SOC2, HIPAA, PCI, etc.)

### Recommended Alternatives for Production/Enterprise Use
For production or enterprise environments, please consider using dedicated secret management solutions such as:
- HashiCorp Vault
- AWS Secrets Manager
- Google Cloud Secret Manager
- Azure Key Vault
- 1Password for Teams
- Doppler
- Keeper Secrets Manager

### Best Practices When Using GistSafe
1. Use strong, unique passwords for each project
2. Regularly rotate your GitHub tokens
3. Never store production credentials
4. Enable key obfuscation for sensitive data
5. Use meaningful but secure password hints
6. Regularly audit your gists and remove unused secrets
7. Monitor GitHub account security (enable 2FA, review access)

By using GistSafe, you acknowledge these limitations and accept responsibility for evaluating whether it meets your security requirements.

## TODO

### Security Enhancements
- [ ] Implement automatic secret rotation capabilities
- [ ] Add comprehensive audit logging for all secret operations
- [ ] Add Multi-Factor Authentication (MFA) support for secret access
- [ ] Implement version control for secrets with history tracking
- [ ] Add secret expiration and automatic renewal
- [ ] Implement fine-grained access control policies
- [ ] Add support for secret value validation (e.g., format checking)
- [ ] Implement rate limiting for failed decryption attempts
- [ ] Add alerts for suspicious access patterns
- [ ] Support for backup and disaster recovery

### Operational Improvements
- [ ] Add support for bulk secret operations
- [ ] Implement secret sharing between teams
- [ ] Add integration with CI/CD pipelines
- [ ] Support for secret templating
- [ ] Add automated backup functionality
- [ ] Implement health checks and monitoring
- [ ] Add support for secret categories and tagging
- [ ] Implement secret usage analytics
- [ ] Add support for secret dependencies and relationships
- [ ] Create migration tools for other secret management systems
