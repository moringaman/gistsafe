"""Core GistSafe secret manager.

Orchestrates encryption, caching, and GitHub Gist operations.
"""

import base64
import json
import os
import subprocess
import sys

from github import Github, InputFileContent

from .cache import CacheManager
from .crypto import decrypt_key, decrypt_value, encrypt_key, encrypt_value
from .display import (
    console,
    display_injection_table,
    display_projects_table,
    display_secrets_table,
)
from .utils import normalize_environment


class GistSafeError(Exception):
    """Base exception for GistSafe operations."""


def _check_password_strength(password: str) -> None:
    """Warn if the password is weak but don't block usage."""
    if len(password) < 8:
        console.print(
            "[yellow]Warning: Password is shorter than 8 characters. "
            "Consider using a stronger password."
        )


def _spawn_cache_refresh(token: str) -> None:
    """Spawn a subprocess to refresh the cache silently.

    Uses a subprocess instead of a thread to avoid daemon-thread
    crashes on stdout during Python interpreter shutdown.
    """
    env = os.environ.copy()
    env["_GISTSAFE_REFRESH_TOKEN"] = token
    subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os; from gistsafe.manager import GistSafe; "
            "GistSafe(os.environ['_GISTSAFE_REFRESH_TOKEN']).refresh_cache()",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _get_rate_info(gh_client):
    """Get core rate limit info, compatible with PyGithub 2.1 - 2.5+.

    PyGithub 2.2+ changed get_rate_limit() return type from RateLimit
    (with .core attribute) to RateLimitOverview (with .rate attribute).
    """
    rl = gh_client.get_rate_limit()
    core = rl.core if hasattr(rl, "core") else rl.rate
    return core.remaining, core.reset


class GistSafe:
    """Manages encrypted secrets stored in private GitHub Gists."""

    def __init__(self, github_token: str) -> None:
        if not github_token:
            raise ValueError("GitHub token is required")

        self._token = github_token
        self.gh = Github(github_token)
        user = self.gh.get_user()
        console.print(f"[green]Authenticated as GitHub user: {user.login}")
        self.user = user
        self.cache = CacheManager()
        self.cache.load()

    def refresh_cache(self) -> None:
        """Fetch all GistSafe gists from GitHub and rebuild the local cache."""
        console.print("[yellow]Refreshing project cache from GitHub...")
        new_cache: dict[str, dict] = {}

        try:
            remaining, reset_dt = _get_rate_info(self.gh)
            console.print(
                f"[blue]GitHub API calls remaining: {remaining} "
                f"(resets at {reset_dt.strftime('%H:%M:%S')})"
            )

            gists = self.user.get_gists()
            total = 0
            found = 0

            for gist in gists:
                total += 1

                has_match = any(
                    "_gistsafe.json" in fname or "_secrets.json" in fname
                    for fname in gist.files
                )
                if not has_match:
                    continue

                found += 1
                console.print(f"[blue]Processing GistSafe gist {found}", end="\r")

                for filename, gist_file in gist.files.items():
                    if "_gistsafe.json" not in filename and "_secrets.json" not in filename:
                        continue

                    try:
                        content = json.loads(gist_file.content)
                        project = content.get("project")
                        environment = content.get("environment")
                        if not project or not environment:
                            continue

                        if project not in new_cache:
                            new_cache[project] = {
                                "environments": {},
                                "gist_url": gist.html_url,
                            }
                        new_cache[project]["environments"][environment] = {
                            "filename": filename,
                            "gist_id": gist.id,
                        }
                        console.print(
                            f"\n[green]Found project: {project} ({environment})"
                        )
                    except (json.JSONDecodeError, Exception):
                        continue

            if total > 0:
                console.print(
                    f"\n[green]Found {found} GistSafe gists in {total} total gists"
                )
            else:
                console.print("[yellow]No gists found")

            self.cache.replace_all(new_cache)

            remaining, reset_dt = _get_rate_info(self.gh)
            console.print(
                f"[blue]Remaining API calls: {remaining} "
                f"(resets at {reset_dt.strftime('%H:%M:%S')})"
            )
        except Exception as e:
            console.print(f"[red]Error refreshing cache: {e}")

    def list_projects(self) -> None:
        """Display all GistSafe projects from cache, refreshing as needed."""
        projects = self.cache.get_all()

        # Empty cache: first run — do sync refresh so user sees results immediately
        if not projects:
            console.print("[yellow]First run — fetching projects from GitHub...")
            self.refresh_cache()
            projects = self.cache.get_all()
            if projects:
                display_projects_table(projects)
            else:
                console.print("[yellow]No GistSafe projects found.")
            return

        display_projects_table(projects)

        # Stale cache: spawn background subprocess to refresh (avoids daemon thread crash)
        if self.cache.needs_refresh():
            console.print("[yellow]Cache is stale. Refreshing in background...")
            _spawn_cache_refresh(self._token)

    def find_gist(self, project: str, environment: str):
        """Find a GistSafe gist for a project and environment.

        Checks cache first, then falls back to a GitHub search.
        Returns a tuple of (gist, content_dict) or (None, None) if not found.
        """
        normalized_env = normalize_environment(environment)

        console.print(f"[yellow]Searching for project: {project}")
        console.print(f"[yellow]Environment (normalized): {normalized_env}")

        cached = self.cache.get(project, normalized_env)
        if cached:
            try:
                gist = self.gh.get_gist(cached["gist_id"])
                content = json.loads(gist.files[cached["filename"]].content)
                console.print(
                    f"[green]Found matching gist with environment: {content['environment']}"
                )
                return gist, content
            except Exception as e:
                console.print(f"[yellow]Cache miss: {e}, searching GitHub...")

        console.print("[yellow]Not found in cache, searching GitHub...")

        possible_envs = {environment.lower(), normalized_env.lower()}
        possible_filenames = [
            f"{project}_{env}_gistsafe.json" for env in possible_envs
        ] + [
            f"{project}_{env}_secrets.json" for env in possible_envs
        ]

        gists = self.user.get_gists().get_page(0)
        for gist in gists:
            for filename in gist.files:
                if filename not in possible_filenames:
                    continue
                try:
                    content = json.loads(gist.files[filename].content)
                    if (
                        content["project"] == project
                        and content["environment"].lower() in possible_envs
                    ):
                        self.cache.update(
                            project,
                            content["environment"],
                            gist.id,
                            filename,
                            gist.html_url,
                        )
                        console.print(
                            f"[green]Found matching gist with environment: {content['environment']}"
                        )
                        return gist, content
                except (json.JSONDecodeError, Exception):
                    continue

        console.print("[red]No matching gist found. Available projects:")
        self.list_projects()
        return None, None

    def create_secret(
        self,
        project: str,
        environment: str,
        secrets: dict[str, str],
        password: str,
        password_hint: str | None = None,
        obfuscate_keys: bool = False,
    ):
        """Create a new encrypted secret gist for a project.

        Args:
            project: Project name.
            environment: Target environment (dev, prod, etc.).
            secrets: Dict of key-value pairs to encrypt and store.
            password: Encryption password.
            password_hint: Optional hint to help remember the password.
            obfuscate_keys: If True, encrypt both keys and values.

        Returns:
            The created GitHub Gist object.
        """
        _check_password_strength(password)

        normalized_env = normalize_environment(environment)
        console.print(f"[yellow]Using normalized environment: {normalized_env}")

        encrypted_secrets: dict[str, str] = {}
        salt = base64.b64encode(os.urandom(16)).decode()

        for key, value in secrets.items():
            enc_val, _ = encrypt_value(value, password, base64.b64decode(salt))
            encoded_val = base64.b64encode(enc_val).decode()

            if obfuscate_keys:
                enc_key = encrypt_key(key, password, base64.b64decode(salt))
                encrypted_secrets[enc_key] = encoded_val
            else:
                encrypted_secrets[key] = encoded_val

        content = {
            "project": project,
            "environment": normalized_env,
            "salt": salt,
            "secrets": encrypted_secrets,
            "password_hint": password_hint,
            "obfuscated": obfuscate_keys,
        }

        filename = f"{project}_{normalized_env}_gistsafe.json"
        description = f"GistSafe: {project} - {environment}"

        console.print("[yellow]Creating gist...")
        console.print(f"[yellow]File name: {filename}")

        try:
            gist = self.user.create_gist(
                description=description,
                public=False,
                files={filename: InputFileContent(json.dumps(content, indent=2))},
            )

            if not gist or not gist.id:
                raise GistSafeError("Failed to create gist - no gist ID returned")

            console.print(f"[green]Created gist {gist.id}")
            console.print(f"[green]Gist URL: {gist.html_url}")

            self.cache.update(project, normalized_env, gist.id, filename, gist.html_url)
            return gist
        except Exception as e:
            console.print(f"[red]Error creating gist: {e}")
            raise

    def update_secret(
        self,
        project: str,
        environment: str,
        secrets: dict[str, str],
        password: str,
        password_hint: str | None = None,
    ):
        """Update an existing gist with new or modified secrets.

        Preserves existing secrets that aren't being updated.
        """
        _check_password_strength(password)

        gist, content = self.find_gist(project, environment)
        if not gist:
            raise GistSafeError(
                f"No gist found for project '{project}' / environment '{environment}'"
            )

        obfuscate_keys = content.get("obfuscated", False)
        salt = base64.b64decode(content["salt"])
        existing_filename = next(iter(gist.files.keys()))

        existing_secrets: dict[str, str] = {}
        for enc_key, enc_val in content["secrets"].items():
            try:
                key = decrypt_key(enc_key, password, salt) if obfuscate_keys else enc_key
                value = decrypt_value(base64.b64decode(enc_val), password, salt)
                existing_secrets[key] = value
            except Exception:
                raise GistSafeError(
                    "Failed to decrypt existing secrets. Check your password."
                )

        existing_secrets.update(secrets)

        encrypted_secrets: dict[str, str] = {}
        for key, value in existing_secrets.items():
            enc_val, _ = encrypt_value(value, password, salt)
            encoded_val = base64.b64encode(enc_val).decode()

            if obfuscate_keys:
                enc_key = encrypt_key(key, password, salt)
                encrypted_secrets[enc_key] = encoded_val
            else:
                encrypted_secrets[key] = encoded_val

        updated_content = {
            "project": project,
            "environment": environment,
            "salt": content["salt"],
            "secrets": encrypted_secrets,
            "password_hint": password_hint or content.get("password_hint"),
            "obfuscated": obfuscate_keys,
        }

        console.print("[yellow]Updating gist...")
        gist.edit(
            description=f"GistSafe: {project} - {environment}",
            files={
                existing_filename: InputFileContent(
                    json.dumps(updated_content, indent=2)
                )
            },
        )
        console.print(f"[green]Updated gist {gist.id}")
        console.print(f"[green]Gist URL: {gist.html_url}")
        return gist

    def get_secrets(
        self, project: str, environment: str, password: str
    ) -> dict[str, str] | None:
        """Retrieve and decrypt secrets for a project/environment."""
        gist, content = self.find_gist(project, environment)
        if not gist:
            console.print("[red]No matching gist found")
            return None

        if content.get("password_hint"):
            console.print(f"[blue]Password hint: {content['password_hint']}")

        obfuscate_keys = content.get("obfuscated", False)
        salt = base64.b64decode(content["salt"])

        decrypted: dict[str, str] = {}
        for enc_key, enc_val in content["secrets"].items():
            try:
                key = decrypt_key(enc_key, password, salt) if obfuscate_keys else enc_key
                value = decrypt_value(base64.b64decode(enc_val), password, salt)
                decrypted[key] = value
            except Exception:
                console.print(f"[red]Failed to decrypt secret")

        if decrypted:
            display_secrets_table(project, environment, decrypted)
            return decrypted

        console.print("[red]No secrets were successfully decrypted")
        return None

    def delete_gist(self, project: str, environment: str) -> bool:
        """Delete a GistSafe gist for a project/environment.

        Removes the gist from GitHub and clears the cache entry.
        Returns True if deleted, False if not found.
        """
        gist, content = self.find_gist(project, environment)
        if not gist:
            console.print("[red]No matching gist found to delete")
            return False

        gist.delete()
        console.print(f"[green]Deleted gist for {project}/{environment}")

        actual_env = content.get("environment", environment)
        with self.cache._lock:
            if project in self.cache._projects:
                envs = self.cache._projects[project].get("environments", {})
                envs.pop(actual_env, None)
                if not envs:
                    self.cache._projects.pop(project, None)
        self.cache.save()
        return True

    def inject_and_run(
        self,
        project: str,
        environment: str,
        password: str,
        command: list[str],
    ) -> int:
        """Decrypt secrets, inject as env vars, and run a command.

        Returns the command's exit code.
        """
        console.print(f"[yellow]Loading secrets for {project} - {environment}...")
        secrets = self.get_secrets(project, environment, password)
        if not secrets:
            console.print("[red]Failed to load secrets. Aborting.")
            return 1

        env = os.environ.copy()
        for key, value in secrets.items():
            env[key.upper()] = value

        display_injection_table(project, environment, secrets)

        try:
            console.print(f"[yellow]Running: {' '.join(command)}")
            result = subprocess.run(
                command,
                env=env,
                check=True,
                text=True,
                capture_output=True,
                shell=False,
            )
            if result.stdout:
                console.print("[green]Command output:")
                console.print(result.stdout.strip())
            if result.stderr:
                console.print("[red]Command errors:")
                console.print(result.stderr.strip())
            return result.returncode
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
            console.print(f"[red]Error running command: {e}")
            return 1
