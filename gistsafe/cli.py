"""Click CLI for GistSafe - secure secret management via GitHub Gists."""

import os
import sys

import click
from dotenv import load_dotenv

from . import keychain as kc
from .display import console
from .manager import GistSafe
from .utils import normalize_environment


def _init_token() -> str | None:
    load_dotenv()
    token = os.getenv("GITHUB_TOKEN")
    if token:
        console.print("[green]Successfully loaded GitHub token from .env file")
    else:
        console.print("[red]No GitHub token found in .env file")
    return token


GITHUB_TOKEN = _init_token()


def _resolve_password(
    project: str, environment: str, explicit: str | None
) -> str | None:
    """Resolve encryption password: explicit arg → keychain → interactive prompt."""
    if explicit:
        return explicit
    pw = kc.get_password(project, environment)
    if pw:
        return pw
    return click.prompt("Encryption password", hide_input=True)


def _prompt_new_password() -> str:
    """Prompt for a new encryption password with confirmation."""
    return click.prompt(
        "Encryption password", hide_input=True, confirmation_prompt=True
    )


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
@click.option("--project", required=True, help="Project name")
@click.option("--environment", required=True, help="Target environment")
@click.option(
    "--password",
    help="Encryption password (prompts if omitted, uses keychain if saved)",
)
@click.option("--password-hint", help="Optional hint to help remember the password")
@click.option(
    "--save-password",
    is_flag=True,
    help="Save the password to your system keychain for future use",
)
@click.option(
    "--obfuscate-keys",
    is_flag=True,
    help="Encrypt both secret keys and values for enhanced security",
)
def create(
    project: str,
    environment: str,
    password: str | None,
    password_hint: str | None,
    save_password: bool,
    obfuscate_keys: bool,
) -> None:
    """Create a new encrypted secret gist for a project."""
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    pw = password or _prompt_new_password()

    try:
        gs = GistSafe(GITHUB_TOKEN)
        secrets: dict[str, str] = {}

        while True:
            key = click.prompt("Enter variable name (or empty to finish)", default="")
            if not key:
                break
            value = click.prompt("Enter secret value", hide_input=True)
            secrets[key] = value

        if not secrets:
            console.print("[yellow]No secrets provided. Exiting.")
            return

        gist = gs.create_secret(
            project, environment, secrets, pw, password_hint, obfuscate_keys
        )
        if gist:
            console.print(
                f"[green]Created secrets for {project} - {environment}"
            )
            if password_hint:
                console.print(f"[blue]Password hint saved: {password_hint}")
            if obfuscate_keys:
                console.print("[blue]Keys are obfuscated for additional security")
            if save_password:
                kc.save_password(project, environment, pw)
    except Exception as e:
        console.print(f"[red]Error: {e}")


@cli.command()
@click.option("--project", required=True, help="Project name")
@click.option("--environment", required=True, help="Target environment")
@click.option(
    "--password",
    help="Encryption password (prompts if omitted, uses keychain if saved)",
)
@click.option("--password-hint", help="Optional new hint")
@click.option(
    "--save-password",
    is_flag=True,
    help="Save/update the password in your system keychain",
)
def update(
    project: str,
    environment: str,
    password: str | None,
    password_hint: str | None,
    save_password: bool,
) -> None:
    """Update existing secrets in a gist."""
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    pw = _resolve_password(project, environment, password)
    if not pw:
        return

    try:
        gs = GistSafe(GITHUB_TOKEN)

        current = gs.get_secrets(project, environment, pw)
        if not current:
            console.print(
                "[red]Could not find or decrypt existing secrets. "
                "Check the project name and password."
            )
            return

        console.print("\n[yellow]Enter new secrets or update existing ones:")
        secrets: dict[str, str] = {}
        while True:
            key = click.prompt("Enter variable name (or empty to finish)", default="")
            if not key:
                break
            value = click.prompt("Enter secret value", hide_input=True)
            secrets[key] = value

        if not secrets:
            console.print("[yellow]No secrets provided. Exiting.")
            return

        gist = gs.update_secret(project, environment, secrets, pw, password_hint)
        if gist:
            console.print(
                f"[green]Updated secrets for {project} - {environment}"
            )
            if password_hint:
                console.print(f"[blue]Password hint updated: {password_hint}")
            if save_password:
                kc.save_password(project, environment, pw)
            gs.get_secrets(project, environment, pw)
    except Exception as e:
        console.print(f"[red]Error: {e}")


@cli.command()
@click.option("--project", required=True, help="Project name")
@click.option("--environment", required=True, help="Target environment")
@click.option(
    "--password",
    help="Encryption password (prompts if omitted, uses keychain if saved)",
)
@click.option(
    "--save-password",
    is_flag=True,
    help="Save the password to your system keychain for future use",
)
def get(project: str, environment: str, password: str | None, save_password: bool) -> None:
    """Retrieve and decrypt secrets from a gist."""
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    pw = _resolve_password(project, environment, password)
    if not pw:
        return

    try:
        gs = GistSafe(GITHUB_TOKEN)
        secrets = gs.get_secrets(project, environment, pw)
        if not secrets:
            console.print(
                "[yellow]No secrets found for the specified project and environment"
            )
        elif save_password:
            kc.save_password(project, environment, pw)
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
    help="Encryption password (prompts if omitted, uses keychain if saved)",
)
@click.option(
    "--save-password",
    is_flag=True,
    help="Save the password to your system keychain for future use",
)
@click.pass_context
def inject(
    ctx: click.Context,
    project: str,
    environment: str | None,
    password: str | None,
    save_password: bool,
) -> None:
    """Inject secrets as environment variables and run a command.

    Usage: gistsafe inject --project <name> [--environment <env>] -- <command> [args...]

    \b
    Examples:
      gistsafe inject --project myapp --environment prod -- npm start
      gistsafe inject --project myapp -- printenv API_KEY
    """
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    env = environment or os.getenv("NODE_ENV", "development")
    normalized_env = normalize_environment(env)
    console.print(f"[yellow]Using environment: {env} (normalized: {normalized_env})")

    pw = _resolve_password(project, normalized_env, password)
    if not pw:
        return

    if save_password:
        kc.save_password(project, normalized_env, pw)

    command_list = ctx.args
    if not command_list:
        console.print("[red]Error: No command provided")
        click.echo(ctx.get_help())
        sys.exit(1)

    try:
        gs = GistSafe(GITHUB_TOKEN)
        console.print(f"[yellow]Executing: {' '.join(command_list)}")
        exit_code = gs.inject_and_run(project, normalized_env, pw, command_list)
        sys.exit(exit_code)
    except Exception as e:
        console.print(f"[red]Error: {e}")
        sys.exit(1)


@cli.command()
@click.option("--project", required=True, help="Project name")
@click.option("--environment", required=True, help="Target environment")
@click.option(
    "--force", is_flag=True, help="Skip confirmation prompt"
)
def delete(project: str, environment: str, force: bool) -> None:
    """Delete a GistSafe project/environment gist permanently."""
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    if not force:
        confirmed = click.confirm(
            f"Permanently delete gist for {project}/{environment}?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Delete cancelled.")
            return

    try:
        gs = GistSafe(GITHUB_TOKEN)
        if gs.delete_gist(project, environment):
            kc.delete_password(project, environment)
    except Exception as e:
        console.print(f"[red]Error: {e}")


@cli.group()
def keychain() -> None:
    """Manage passwords stored in the system keychain."""


@keychain.command("forget")
@click.option("--project", required=True, help="Project name")
@click.option("--environment", required=True, help="Target environment")
def keychain_forget(project: str, environment: str) -> None:
    """Remove a saved password from the system keychain."""
    kc.delete_password(project, environment)


@cli.command()
def list() -> None:
    """List all available GistSafe projects and environments."""
    if not GITHUB_TOKEN:
        console.print("[red]Error: GITHUB_TOKEN environment variable not set")
        return

    try:
        gs = GistSafe(GITHUB_TOKEN)
        gs.list_projects()
    except Exception as e:
        console.print(f"[red]Error: {e}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
