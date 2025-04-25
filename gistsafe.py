#!/usr/bin/env python3

import os
import json
import base64
import click
import time
import threading
import subprocess
from rich.console import Console
from rich.table import Table
from github import Github, InputFileContent
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

console = Console()

# Load environment variables at the start
load_dotenv()
github_token = os.getenv('GITHUB_TOKEN')
if github_token:
    console.print("[green]Successfully loaded GitHub token from .env file")
    # Print first and last 4 characters of token for verification
    console.print(f"[green]Token starts with '{github_token[:4]}' and ends with '{github_token[-4:]}'")
else:
    console.print("[red]No GitHub token found in .env file")

def generate_key(password: str, salt: bytes = None) -> tuple:
    """Generate a Fernet key from a password."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key), salt

def encrypt_value(value: str, password: str, salt: bytes = None) -> tuple:
    """Encrypt a value using Fernet encryption."""
    f, salt = generate_key(password, salt)
    encrypted_value = f.encrypt(value.encode())
    return encrypted_value, salt

def decrypt_value(encrypted_value: bytes, password: str, salt: bytes) -> str:
    """Decrypt a value using Fernet encryption."""
    f, _ = generate_key(password, salt)
    return f.decrypt(encrypted_value).decode()

def encrypt_key(key: str, password: str, salt: bytes) -> str:
    """Encrypt a key using the same encryption method as values."""
    f, _ = generate_key(password, salt)
    encrypted_key = f.encrypt(key.encode())
    return base64.b64encode(encrypted_key).decode()

def decrypt_key(encrypted_key: str, password: str, salt: bytes) -> str:
    """Decrypt a key using the same encryption method as values."""
    f, _ = generate_key(password, salt)
    return f.decrypt(base64.b64decode(encrypted_key)).decode()

def normalize_environment(env: str) -> str:
    """Normalize environment names to handle common variations."""
    env_mapping = {
        'dev': 'development',
        'prod': 'production',
        'stage': 'staging',
        'qa': 'testing',
    }
    
    # Convert to lowercase for consistent matching
    env = env.lower()
    
    # If it's a known short form, convert it
    if env in env_mapping:
        return env_mapping[env]
    
    # Otherwise return the original (lowercase)
    return env

class GistSafe:
    def __init__(self, github_token: str):
        if not github_token:
            raise ValueError("GitHub token is required")
        try:
            self.gh = Github(github_token)
            # Test the connection
            user = self.gh.get_user()
            console.print(f"[green]Successfully authenticated as GitHub user: {user.login}")
            self.user = user
            
            # Initialize cache
            self.cache_file = os.path.expanduser('~/.gistsafe/cache.json')
            self.cache_dir = os.path.dirname(self.cache_file)
            if not os.path.exists(self.cache_dir):
                os.makedirs(self.cache_dir)
            
            # Initialize threading lock for cache operations
            self._cache_lock = threading.Lock()
            self._refresh_thread = None
            self.cache = {}
            
            # Load cache initially
            self.load_cache()
        except Exception as e:
            console.print(f"[red]Error connecting to GitHub: {str(e)}")
            raise

    def load_cache(self):
        """Load the cache from disk."""
        try:
            if os.path.exists(self.cache_file):
                console.print(f"[yellow]Loading cache from: {self.cache_file}")
                with self._cache_lock:
                    with open(self.cache_file, 'r') as f:
                        cache_data = json.load(f)
                        self.cache = cache_data.get('projects', {})
                        last_update = cache_data.get('last_update', 0)
                        
                        console.print(f"[green]Loaded {len(self.cache)} projects from cache")
                        
                        # Cache expires after 1 hour
                        if time.time() - last_update > 3600:
                            console.print("[yellow]Cache is older than 1 hour, refreshing...")
                            self.cache = self._refresh_cache_sync()
            else:
                console.print("[yellow]No cache file found, creating new cache...")
                self.cache = self._refresh_cache_sync()
        except json.JSONDecodeError as e:
            console.print(f"[red]Error decoding cache file: {str(e)}")
            console.print("[yellow]Refreshing cache due to corruption...")
            self.cache = self._refresh_cache_sync()
        except Exception as e:
            console.print(f"[red]Error loading cache: {str(e)}")
            console.print("[yellow]Starting with empty cache...")
            self.cache = {}

    def save_cache(self):
        """Save the cache to disk with synchronous verification."""
        try:
            # Ensure cache directory exists with explicit permissions
            if not os.path.exists(self.cache_dir):
                console.print(f"[yellow]Creating cache directory: {self.cache_dir}")
                os.makedirs(self.cache_dir, mode=0o755, exist_ok=True)
            
            # Verify directory is writable
            if not os.access(self.cache_dir, os.W_OK):
                console.print(f"[red]Cache directory is not writable: {self.cache_dir}")
                return False
            
            console.print(f"[yellow]Saving cache to: {self.cache_file}")
            
            # Prepare cache data
            cache_data = {
                'projects': self.cache,
                'last_update': time.time()
            }
            
            # Write to file
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            # Verify the file exists and has content
            if os.path.exists(self.cache_file):
                size = os.path.getsize(self.cache_file)
                if size > 0:
                    console.print(f"[green]Cache saved successfully ({size} bytes)")
                    # Verify we can read it back
                    with open(self.cache_file, 'r') as f:
                        test_read = json.load(f)
                        if test_read.get('projects') == self.cache:
                            console.print("[green]Cache verification successful")
                            return True
                        else:
                            console.print("[red]Cache verification failed - content mismatch")
                            return False
                else:
                    console.print("[red]Cache file is empty!")
                    return False
            else:
                console.print("[red]Cache file was not created!")
                return False
                
        except PermissionError as e:
            console.print(f"[red]Permission denied when saving cache: {str(e)}")
            console.print(f"[yellow]Cache directory: {self.cache_dir}")
            console.print(f"[yellow]Cache file: {self.cache_file}")
            console.print(f"[yellow]Current user: {os.getenv('USER')}")
            return False
        except Exception as e:
            console.print(f"[red]Error saving cache: {str(e)}")
            console.print(f"[yellow]Cache directory: {self.cache_dir}")
            console.print(f"[yellow]Cache file: {self.cache_file}")
            console.print(f"[yellow]Error type: {type(e).__name__}")
            return False

    def _refresh_cache_sync(self):
        """Synchronous cache refresh implementation."""
        console.print("[yellow]Refreshing project cache from GitHub...")
        new_cache = {}
        try:
            # Show rate limit info
            rate_limit = self.gh.get_rate_limit()
            remaining = rate_limit.core.remaining
            reset_time = rate_limit.core.reset.strftime('%H:%M:%S')
            console.print(f"[blue]GitHub API calls remaining: {remaining} (resets at {reset_time})")
            
            # Get user's gists and filter by filename
            gists = self.user.get_gists()
            total_gists = 0
            secret_gists_found = 0
            
            # Process gists but use filename filtering first
            for gist in gists:
                total_gists += 1
                
                # Quick check if any file matches our patterns before processing content
                has_matching_file = any(
                    '_gistsafe.json' in filename or '_secrets.json' in filename
                    for filename in gist.files.keys()
                )
                
                if not has_matching_file:
                    continue
                
                # Show progress for matching gists
                secret_gists_found += 1
                console.print(f"[blue]Processing GistSafe gist {secret_gists_found}", end='\r')
                
                for filename, file in gist.files.items():
                    if '_gistsafe.json' in filename or '_secrets.json' in filename:
                        try:
                            content = json.loads(file.content)
                            project = content.get("project")
                            environment = content.get("environment")
                            
                            if not project or not environment:
                                continue
                            
                            if project not in new_cache:
                                new_cache[project] = {
                                    "environments": {},
                                    "gist_url": gist.html_url
                                }
                            
                            new_cache[project]["environments"][environment] = {
                                "filename": filename,
                                "gist_id": gist.id
                            }
                            console.print(f"\n[green]Found project: {project} ({environment})")
                        except json.JSONDecodeError:
                            continue
                        except Exception as e:
                            console.print(f"\n[red]Error parsing gist {filename}: {str(e)}")
                            continue
            
            # Show final stats
            if total_gists > 0:
                console.print(f"\n[green]Found {secret_gists_found} GistSafe gists in {total_gists} total gists")
            else:
                console.print("[yellow]No gists found")
            
            # Update the cache atomically and ensure it's saved
            with self._cache_lock:
                self.cache = new_cache
                if self.save_cache():  # Only proceed if cache was saved successfully
                    if new_cache:
                        console.print("[green]Cache refresh complete")
                    else:
                        console.print("[yellow]No GistSafe projects found in any gists")
                else:
                    console.print("[red]Failed to save cache!")
                    
            # Show rate limit status after completion
            rate_limit = self.gh.get_rate_limit()
            remaining = rate_limit.core.remaining
            reset_time = rate_limit.core.reset.strftime('%H:%M:%S')
            console.print(f"[blue]Remaining GitHub API calls: {remaining} (resets at {reset_time})")
            
            return new_cache
            
        except Exception as e:
            console.print(f"[red]Error refreshing cache: {str(e)}")
            return {}

    def _display_projects_table(self):
        """Display the projects table."""
        if not self.cache:
            console.print("[yellow]No GistSafe projects found")
            return
            
        # Create and display the projects table
        table = Table(title="Available GistSafe Projects")
        table.add_column("Project", style="cyan")
        table.add_column("Environments", style="green")
        table.add_column("Gist URL", style="blue")
        
        # Sort projects for consistent display
        for project, data in sorted(self.cache.items()):
            environments = ", ".join(sorted(data["environments"].keys()))
            table.add_row(project, environments, data["gist_url"])
        
        console.print("\n[bold]Found GistSafe Projects:[/bold]")
        console.print(table)

    def update_cache_for_project(self, project: str, environment: str, gist_id: str, filename: str, gist_url: str):
        """Update cache for a specific project."""
        with self._cache_lock:
            if project not in self.cache:
                self.cache[project] = {
                    "environments": {},
                    "gist_url": gist_url
                }
            
            self.cache[project]["environments"][environment] = {
                "filename": filename,
                "gist_id": gist_id
            }
            
            self.save_cache()

    def list_projects(self):
        """List all available GistSafe projects and their environments."""
        if not self.cache:
            self.load_cache()  # This will do a sync refresh if needed
        
        self._display_projects_table()

    def find_gist(self, project: str, environment: str):
        """Find a gist for a specific project and environment."""
        if not self.cache:
            self.load_cache()
        
        normalized_env = normalize_environment(environment)
        
        # Debug: Show what we're looking for
        console.print(f"[yellow]Searching for project: {project}")
        console.print(f"[yellow]Environment (normalized): {normalized_env}")
        
        # Check cache first
        cached_data = self.get_from_cache(project, normalized_env)
        if cached_data:
            try:
                gist = self.gh.get_gist(cached_data["gist_id"])
                content = json.loads(gist.files[cached_data["filename"]].content)
                console.print(f"[green]Found matching gist with environment: {content['environment']}")
                return gist, content
            except Exception as e:
                console.print(f"[yellow]Cache error: {str(e)}, refreshing...")
                self._refresh_cache_sync()
        
        # If not found in cache or cache error, do a targeted search
        console.print("[yellow]Not found in cache, searching GitHub...")
        
        # Try all possible environment name variations
        possible_envs = {environment.lower(), normalized_env.lower()}
        possible_filenames = [
            f"{project}_{env}_gistsafe.json" for env in possible_envs
        ] + [
            f"{project}_{env}_secrets.json" for env in possible_envs
        ]
        
        # Get only the first page of gists for efficiency
        gists = self.user.get_gists().get_page(0)
        for gist in gists:
            for filename, file in gist.files.items():
                if filename in possible_filenames:
                    try:
                        content = json.loads(file.content)
                        if (content["project"] == project and 
                            content["environment"].lower() in possible_envs):
                            # Update cache with found gist
                            self.update_cache_for_project(
                                project,
                                content["environment"],
                                gist.id,
                                filename,
                                gist.html_url
                            )
                            console.print(f"[green]Found matching gist with environment: {content['environment']}")
                            return gist, content
                    except Exception:
                        continue
        
        console.print("[red]No matching gist found. Available projects:")
        self.list_projects()
        return None, None

    def create_secret(self, project: str, environment: str, secrets: dict, password: str, password_hint: str = None, obfuscate_keys: bool = False):
        """Create a new secret gist for a project and environment."""
        # Normalize environment name for storage
        normalized_env = normalize_environment(environment)
        console.print(f"[yellow]Using normalized environment name: {normalized_env}")
        
        encrypted_secrets = {}
        salt = os.urandom(16)

        for key, value in secrets.items():
            encrypted_value, _ = encrypt_value(value, password, salt)
            if obfuscate_keys:
                encrypted_key = encrypt_key(key, password, salt)
                encrypted_secrets[encrypted_key] = base64.b64encode(encrypted_value).decode()
            else:
                encrypted_secrets[key] = base64.b64encode(encrypted_value).decode()

        content = {
            "project": project,
            "environment": normalized_env,  # Store normalized name
            "salt": base64.b64encode(salt).decode(),
            "secrets": encrypted_secrets,
            "password_hint": password_hint,
            "obfuscated": obfuscate_keys
        }

        description = f"GistSafe: {project} - {environment}"
        try:
            filename = f"{project}_{normalized_env}_gistsafe.json"
            file_content = json.dumps(content, indent=2)
            
            console.print("[yellow]Creating gist...")
            console.print(f"[yellow]File name: {filename}")
            
            gist = self.user.create_gist(
                description=description,
                public=False,
                files={
                    filename: InputFileContent(file_content)
                }
            )
            
            if not gist or not gist.id:
                raise Exception("Failed to create gist - no gist ID returned")
                
            console.print(f"[green]Successfully created gist with ID: {gist.id}")
            console.print(f"[green]Gist URL: {gist.html_url}")
            
            # After successful creation, update cache
            self.update_cache_for_project(
                project,
                normalized_env,
                gist.id,
                filename,
                gist.html_url
            )
            
            return gist
        except Exception as e:
            console.print(f"[red]Error creating gist: {str(e)}")
            if hasattr(e, 'data'):
                console.print(f"[red]API Response: {e.data}")
            raise

    def update_secret(self, project: str, environment: str, secrets: dict, password: str, password_hint: str = None):
        """Update an existing gist with new or modified secrets."""
        gist, content = self.find_gist(project, environment)
        if not gist:
            raise ValueError(f"No gist found for project '{project}' and environment '{environment}'")

        # Get obfuscation setting from existing content
        obfuscate_keys = content.get("obfuscated", False)
        
        # Decrypt existing secrets
        existing_secrets = {}
        salt = base64.b64decode(content["salt"])
        for enc_key, encrypted_value in content["secrets"].items():
            try:
                key = decrypt_key(enc_key, password, salt) if obfuscate_keys else enc_key
                decrypted_value = decrypt_value(
                    base64.b64decode(encrypted_value),
                    password,
                    salt
                )
                existing_secrets[key] = decrypted_value
            except Exception as e:
                console.print(f"[red]Error decrypting secret: {str(e)}")
                raise ValueError("Failed to decrypt existing secrets. Make sure you're using the correct password.")

        # Update existing secrets with new values
        existing_secrets.update(secrets)

        # Encrypt all secrets with the same salt
        encrypted_secrets = {}
        for key, value in existing_secrets.items():
            encrypted_value, _ = encrypt_value(value, password, salt)
            if obfuscate_keys:
                encrypted_key = encrypt_key(key, password, salt)
                encrypted_secrets[encrypted_key] = base64.b64encode(encrypted_value).decode()
            else:
                encrypted_secrets[key] = base64.b64encode(encrypted_value).decode()

        # Update content
        updated_content = {
            "project": project,
            "environment": environment,
            "salt": content["salt"],  # Keep the same salt
            "secrets": encrypted_secrets,
            "password_hint": password_hint or content.get("password_hint"),
            "obfuscated": obfuscate_keys
        }

        try:
            filename = f"{project}_{environment}_secrets.json"
            file_content = json.dumps(updated_content, indent=2)
            
            console.print("[yellow]Updating gist...")
            gist.edit(
                description=f"GistSafe: {project} - {environment}",
                files={
                    filename: InputFileContent(file_content)
                }
            )
            
            console.print(f"[green]Successfully updated gist with ID: {gist.id}")
            console.print(f"[green]Gist URL: {gist.html_url}")
            return gist
        except Exception as e:
            console.print(f"[red]Error updating gist: {str(e)}")
            if hasattr(e, 'data'):
                console.print(f"[red]API Response: {e.data}")
            raise

    def get_secrets(self, project: str, environment: str, password: str):
        """Retrieve and decrypt secrets for a project and environment."""
        gist, content = self.find_gist(project, environment)
        if not gist:
            console.print("[red]No matching gist found")
            return None

        # Display password hint if available
        if "password_hint" in content and content["password_hint"]:
            console.print(f"[blue]Password hint: {content['password_hint']}")

        obfuscate_keys = content.get("obfuscated", False)
        salt = base64.b64decode(content["salt"])
        decrypted_secrets = {}
        
        for enc_key, encrypted_value in content["secrets"].items():
            try:
                key = decrypt_key(enc_key, password, salt) if obfuscate_keys else enc_key
                decrypted_value = decrypt_value(
                    base64.b64decode(encrypted_value),
                    password,
                    salt
                )
                decrypted_secrets[key] = decrypted_value
            except Exception as e:
                console.print(f"[red]Error decrypting secret: {str(e)}")
        
        if decrypted_secrets:
            table = Table(title=f"Secrets for {project} - {environment}")
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="green")
            
            for key, value in decrypted_secrets.items():
                table.add_row(key, value)
            
            console.print(table)
            return decrypted_secrets
        else:
            console.print("[red]No secrets were successfully decrypted")
            return None

    def inject_and_run(self, project: str, environment: str, password: str, command: list):
        """Inject secrets into environment and run a command."""
        console.print(f"[yellow]Loading secrets for {project} - {environment}...")
        secrets = self.get_secrets(project, environment, password)
        if not secrets:
            console.print("[red]Failed to load secrets. Aborting command execution.")
            return

        # Create a new environment with current env vars plus our secrets
        env = os.environ.copy()
        
        # Create a table to show injected variables
        table = Table(title=f"Injected Environment Variables for {project} - {environment}")
        table.add_column("Environment Variable", style="cyan")
        table.add_column("Value", style="green")
        
        # Debug: Show original secrets
        console.print("[yellow]Original secrets:")
        for k, v in secrets.items():
            console.print(f"[yellow]  {k} = {v}")
        
        for key, value in secrets.items():
            env_key = key.upper()
            env[env_key] = value
            # Show first 4 and last 4 chars of value if longer than 12 chars
            display_value = value if len(value) <= 12 else f"{value[:4]}...{value[-4:]}"
            table.add_row(env_key, display_value)
            # Debug: Confirm environment variable was set
            console.print(f"[yellow]Set environment variable {env_key}={env.get(env_key, 'NOT SET!')}")
        
        console.print(table)

        try:
            # Run the command with the modified environment
            console.print(f"[yellow]Running command: {' '.join(command)}")
            
            # Debug: If we're looking for a specific env var, show its state
            if len(command) == 2 and command[0] == 'printenv':
                var_name = command[1]
                console.print(f"[yellow]Checking environment variable: {var_name}")
                console.print(f"[yellow]Available in env: {var_name in env}")
                console.print(f"[yellow]Current value: {env.get(var_name, 'NOT FOUND')}")
                console.print(f"[yellow]All available env vars: {sorted([k for k in env.keys() if k.startswith('TEST')])}")
            
            process = subprocess.run(
                command,
                env=env,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False  # Ensure we're not using shell expansion
            )
            
            if process.stdout:
                console.print("[green]Command output:")
                console.print(process.stdout.strip())
            if process.stderr:
                console.print("[red]Command errors:")
                console.print(process.stderr.strip())
            
            return process.returncode
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Command failed with exit code {e.returncode}")
            if e.stdout:
                console.print("[yellow]Command output:")
                console.print(e.stdout.strip())
            if e.stderr:
                console.print("[red]Command errors:")
                console.print(e.stderr.strip())
            return e.returncode
        except Exception as e:
            console.print(f"[red]Error running command: {str(e)}")
            return 1

    def get_from_cache(self, project: str, environment: str):
        """Thread-safe method to get data from cache."""
        with self._cache_lock:
            if project in self.cache:
                project_data = self.cache[project]
                for env, env_data in project_data["environments"].items():
                    if env.lower() in [environment.lower(), normalize_environment(environment).lower()]:
                        return env_data
        return None

@click.group()
def cli():
    """GistSafe - Secure secret management using GitHub Gists

    GistSafe provides a secure way to store and manage secrets using GitHub Gists as the backend.
    All secrets are encrypted before storage and can only be decrypted with the correct password.

    Common Environment Names:
    - dev, development
    - prod, production
    - stage, staging
    - qa, testing

    Example Usage:
      $ gistsafe create --project myapp --environment dev
      $ gistsafe get --project myapp --environment prod
      $ gistsafe list
      $ gistsafe inject --project myapp npm start
    """
    pass

@cli.command()
@click.option('--project', required=True, help='Name of your project (e.g., myapp, backend-api)')
@click.option('--environment', required=True, help='Target environment (dev, prod, staging, etc.)')
@click.option('--password', required=True, prompt=True, hide_input=True,
              help='Encryption password for the secrets')
@click.option('--password-hint', help='Optional hint to help remember the password (do not include the actual password)')
@click.option('--obfuscate-keys', is_flag=True, help='Encrypt both secret keys and values for enhanced security')
def create(project, environment, password, password_hint, obfuscate_keys):
    """Create a new encrypted secret gist for a project.

    This command creates a new private GitHub gist containing encrypted secrets
    for your project. You will be prompted to enter secret key-value pairs
    interactively.

    Examples:
        $ gistsafe create --project myapp --environment dev
        $ gistsafe create --project backend-api --environment prod --password-hint "Company vault master key"
        $ gistsafe create --project sensitive-app --environment prod --obfuscate-keys

    The command will:
    1. Create a new private gist
    2. Encrypt all secrets with your password
    3. Store the encrypted data in the gist
    4. Update the local cache
    """
    if not github_token:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gist_safe = GistSafe(github_token)
        secrets = {}
        
        while True:
            key = click.prompt('Enter secret key (or empty to finish)', default='')
            if not key:
                break
            value = click.prompt('Enter secret value', hide_input=True)
            secrets[key] = value

        if not secrets:
            console.print("[yellow]No secrets provided. Exiting...")
            return

        gist = gist_safe.create_secret(project, environment, secrets, password, password_hint, obfuscate_keys)
        if gist:
            console.print(f"[green]Successfully created secrets for {project} - {environment}")
            if password_hint:
                console.print(f"[blue]Password hint saved: {password_hint}")
            if obfuscate_keys:
                console.print("[blue]Keys are obfuscated for additional security")
            console.print(f"[green]You can view your gist at: {gist.html_url}")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}")

@cli.command()
@click.option('--project', required=True, help='Name of your project (e.g., myapp, backend-api)')
@click.option('--environment', required=True, help='Target environment (dev, prod, staging, etc.)')
@click.option('--password', required=True, prompt=True, hide_input=True,
              help='Encryption password used when creating the secrets')
@click.option('--password-hint', help='Optional new hint to help remember the password')
def update(project, environment, password, password_hint):
    """Update existing secrets in a gist.

    This command allows you to add new secrets or update existing ones in
    a project's gist. You must provide the same password that was used
    when creating the secrets.

    Examples:
        $ gistsafe update --project myapp --environment dev
        $ gistsafe update --project backend-api --environment prod --password-hint "New hint"

    The command will:
    1. Show current secrets (if decryption is successful)
    2. Prompt for new or updated secrets
    3. Preserve any existing secrets not being updated
    4. Update the gist with the new encrypted data
    """
    if not github_token:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gist_safe = GistSafe(github_token)
        
        # First, show current secrets
        current_secrets = gist_safe.get_secrets(project, environment, password)
        if not current_secrets:
            console.print("[red]Could not find or decrypt existing secrets. Make sure the project exists and you're using the correct password.")
            return

        console.print("\n[yellow]Enter new secrets or update existing ones:")
        secrets = {}
        
        while True:
            key = click.prompt('Enter secret key (or empty to finish)', default='')
            if not key:
                break
            value = click.prompt('Enter secret value', hide_input=True)
            secrets[key] = value

        if not secrets:
            console.print("[yellow]No secrets provided. Exiting...")
            return

        gist = gist_safe.update_secret(project, environment, secrets, password, password_hint)
        if gist:
            console.print(f"[green]Successfully updated secrets for {project} - {environment}")
            if password_hint:
                console.print(f"[blue]Password hint updated: {password_hint}")
            console.print(f"[green]You can view your gist at: {gist.html_url}")
            
            # Show updated secrets
            gist_safe.get_secrets(project, environment, password)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}")

@cli.command()
@click.option('--project', required=True, help='Name of your project (e.g., myapp, backend-api)')
@click.option('--environment', required=True, help='Target environment (dev, prod, staging, etc.)')
@click.option('--password', required=True, prompt=True, hide_input=True,
              help='Encryption password used when creating the secrets')
def get(project, environment, password):
    """Retrieve and decrypt secrets from a gist.

    This command fetches the encrypted secrets from the project's gist
    and decrypts them using the provided password. If a password hint
    was set, it will be displayed before the password prompt.

    Examples:
        $ gistsafe get --project myapp --environment dev
        $ gistsafe get --project backend-api --environment prod

    The command will:
    1. Find the project's gist (using cache if available)
    2. Decrypt the secrets using your password
    3. Display the decrypted secrets in a table
    """
    if not github_token:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gist_safe = GistSafe(github_token)
        secrets = gist_safe.get_secrets(project, environment, password)

        if not secrets:
            console.print("[yellow]No secrets found for the specified project and environment")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}")

@cli.command()
@click.option('--project', required=True, help='Name of your project (e.g., myapp, backend-api)')
@click.option('--password', required=True, prompt=True, hide_input=True,
              help='Encryption password used when creating the secrets')
@click.argument('command', nargs=-1, required=True)
def inject(project, password, command):
    """Inject secrets as environment variables and run a command.

    This command decrypts the project's secrets and injects them as
    environment variables before running your specified command. The
    environment is determined by NODE_ENV (defaults to 'development').

    Examples:
        $ export NODE_ENV=production
        $ gistsafe inject --project myapp npm start
        $ gistsafe inject --project backend-api python app.py
        $ gistsafe inject --project myapp printenv API_KEY

    The command will:
    1. Load secrets for the project and environment
    2. Convert secret keys to uppercase
    3. Add them as environment variables
    4. Run your specified command with the enhanced environment
    5. Display which variables were injected (with masked values)

    Note: Secret keys are converted to uppercase, so a secret named
    'api_key' becomes the environment variable 'API_KEY'.
    """
    if not github_token:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    # Get environment from NODE_ENV, default to 'development'
    environment = os.getenv('NODE_ENV', 'development')
    normalized_env = normalize_environment(environment)
    console.print(f"[yellow]Using environment: {environment} (normalized: {normalized_env})")

    try:
        gist_safe = GistSafe(github_token)
        # Convert command tuple to list for subprocess
        command_list = list(command)
        console.print(f"[yellow]Executing command: {' '.join(command_list)}")
        return_code = gist_safe.inject_and_run(project, normalized_env, password, command_list)
        exit(return_code)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}")
        exit(1)

@cli.command()
def list():
    """List all available GistSafe projects and environments.

    This command displays a table of all projects and their available
    environments that GistSafe can access. It uses a local cache for
    fast retrieval and updates asynchronously in the background.

    Examples:
        $ gistsafe list

    The command will show:
    1. Project names
    2. Available environments for each project
    3. Gist URLs for easy access

    Note: The cache automatically refreshes when:
    - It is older than 1 hour
    - A cache lookup fails
    - New secrets are created or updated
    """
    if not github_token:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gist_safe = GistSafe(github_token)
        gist_safe.list_projects()
    except Exception as e:
        console.print(f"[red]Error: {str(e)}")
        exit(1)

if __name__ == '__main__':
    cli() 