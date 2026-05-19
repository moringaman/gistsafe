"""Click CLI for GistSafe - secure secret management via GitHub Gists."""

import os
import sys

import click
from dotenv import load_dotenv

from .display import console
from .manager import GistSafe
from .utils import normalize_environment


def _init_token() -> str | None:
    """Load GitHub token from environment."""
    load_dotenv()
    token = os.getenv("GITHUB_TOKEN")
    if token:
        console.print("[green]Successfully loaded GitHub token from .env file")
    else:
        console.print("[red]No GitHub token found in .env file")
    return token


GITHUB_TOKEN = _init_token()


@click.group()
def cli() -> None:
    """GistSafe - Secure secret management using GitHub Gists.

    Encrypts environment variables and stores them in private GitHub Gists.
    Secrets are encrypted client-side and never transmitted in plaintext.

    \b
    Environment short forms:
      dev   -> development
      prod  -> production
      stage -> staging
      qa    -> testing
    """


@cli.command()
@click.option(
    "--project", required=True, help="Project name (e.g., myapp, backend-api)"
)
@click.option(
    "--environment",
    required=True,
    help="Target environment (dev, prod, staging, etc.)",
)
@click.option(
    "--password",
    required=True,
    prompt=True,
    hide_input=True,
    help="Encryption password for the secrets",
)
@click.option(
    "--password-hint",
    help="Optional hint to help remember the password",
)
@click.option(
    "--obfuscate-keys",
    is_flag=True,
    help="Encrypt both secret keys and values for enhanced security",
)
def create(
    project: str,
    environment: str,
    password: str,
    password_hint: str | None,
    obfuscate_keys: bool,
) -> None:
    """Create a new encrypted secret gist for a project.

    Prompts interactively for secret key-value pairs.
    Secrets are encrypted with your password before storage.
    """
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gs = GistSafe(GITHUB_TOKEN)
        secrets: dict[str, str] = {}

        while True:
            key = click.prompt("Enter secret key (or empty to finish)", default="")
            if not key:
                break
            value = click.prompt("Enter secret value", hide_input=True)
            secrets[key] = value

        if not secrets:
            console.print("[yellow]No secrets provided. Exiting.")
            return

        gist = gs.create_secret(
            project, environment, secrets, password, password_hint, obfuscate_keys
        )
        if gist:
            console.print(
                f"[green]Successfully created secrets for {project} - {environment}"
            )
            if password_hint:
                console.print(f"[blue]Password hint saved: {password_hint}")
            if obfuscate_keys:
                console.print("[blue]Keys are obfuscated for additional security")
    except Exception as e:
        console.print(f"[red]Error: {e}")


@cli.command()
@click.option("--project", required=True, help="Project name")
@click.option(
    "--environment", required=True, help="Target environment"
)
@click.option(
    "--password",
    required=True,
    prompt=True,
    hide_input=True,
    help="Encryption password used when creating the secrets",
)
@click.option(
    "--password-hint",
    help="Optional new hint to help remember the password",
)
def update(
    project: str,
    environment: str,
    password: str,
    password_hint: str | None,
) -> None:
    """Update existing secrets in a gist.

    Shows current secrets, then prompts for new or updated values.
    Preserves any secrets you don't modify.
    """
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gs = GistSafe(GITHUB_TOKEN)

        current = gs.get_secrets(project, environment, password)
        if not current:
            console.print(
                "[red]Could not find or decrypt existing secrets. "
                "Check the project name and password."
            )
            return

        console.print("\n[yellow]Enter new secrets or update existing ones:")
        secrets: dict[str, str] = {}
        while True:
            key = click.prompt("Enter secret key (or empty to finish)", default="")
            if not key:
                break
            value = click.prompt("Enter secret value", hide_input=True)
            secrets[key] = value

        if not secrets:
            console.print("[yellow]No secrets provided. Exiting.")
            return

        gist = gs.update_secret(project, environment, secrets, password, password_hint)
        if gist:
            console.print(
                f"[green]Successfully updated secrets for {project} - {environment}"
            )
            if password_hint:
                console.print(f"[blue]Password hint updated: {password_hint}")
            gs.get_secrets(project, environment, password)
    except Exception as e:
        console.print(f"[red]Error: {e}")


@cli.command()
@click.option("--project", required=True, help="Project name")
@click.option(
    "--environment", required=True, help="Target environment"
)
@click.option(
    "--password",
    required=True,
    prompt=True,
    hide_input=True,
    help="Encryption password used when creating the secrets",
)
def get(project: str, environment: str, password: str) -> None:
    """Retrieve and decrypt secrets from a gist.

    If a password hint was set, it will be displayed before the prompt.
    """
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gs = GistSafe(GITHUB_TOKEN)
        secrets = gs.get_secrets(project, environment, password)
        if not secrets:
            console.print(
                "[yellow]No secrets found for the specified project and environment"
            )
    except Exception as e:
        console.print(f"[red]Error: {e}")


@cli.command(
    context_settings={
        "ignore_unknown_options": True,
        "allow_extra_args": True,
        "allow_interspersed_args": True,
    }
)
@click.option("--project", required=True, help="Project name")
@click.option(
    "--environment",
    help="Target environment. Defaults to NODE_ENV or 'development'",
)
@click.option(
    "--password",
    required=True,
    prompt=True,
    hide_input=True,
    help="Encryption password",
)
@click.pass_context
def inject(
    ctx: click.Context,
    project: str,
    environment: str | None,
    password: str,
) -> None:
    """Inject secrets as environment variables and run a command.

    Usage: gistsafe inject --project <name> [--environment <env>] -- <command> [args...]

    \b
    Examples:
      gistsafe inject --project myapp --environment prod -- npm start
      gistsafe inject --project backend-api -- python app.py
      gistsafe inject --project myapp -- printenv API_KEY
    """
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    env = environment or os.getenv("NODE_ENV", "development")
    normalized_env = normalize_environment(env)
    console.print(f"[yellow]Using environment: {env} (normalized: {normalized_env})")

    command_list = ctx.args
    if not command_list:
        console.print("[red]Error: No command provided")
        click.echo(ctx.get_help())
        sys.exit(1)

    try:
        gs = GistSafe(GITHUB_TOKEN)
        console.print(f"[yellow]Executing: {' '.join(command_list)}")
        exit_code = gs.inject_and_run(project, normalized_env, password, command_list)
        sys.exit(exit_code)
    except Exception as e:
        console.print(f"[red]Error: {e}")
        sys.exit(1)


@cli.command()
def list() -> None:
    """List all available GistSafe projects and environments.

    Displays a table of projects, their environments, and gist URLs.
    Uses a local cache with automatic background refresh.
    """
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gs = GistSafe(GITHUB_TOKEN)
        gs.list_projects()
    except Exception as e:
        console.print(f"[red]Error: {e}")


def main() -> None:
    """Entry point for console_scripts."""
    cli()


if __name__ == "__main__":
    main()
