"""System keychain integration for storing project encryption passwords."""

import keyring

from .display import console

SERVICE_NAME = "gistsafe"
_TOKEN_ENTRY = "__github_token__"


def _entry_name(project: str, environment: str) -> str:
    return f"{project}/{environment}"


def save_password(project: str, environment: str, password: str) -> None:
    """Store a project password in the system keychain."""
    entry = _entry_name(project, environment)
    keyring.set_password(SERVICE_NAME, entry, password)
    console.print(f"[green]Password saved to keychain for {entry}")


def get_password(project: str, environment: str) -> str | None:
    """Retrieve a project password from the system keychain, or None."""
    entry = _entry_name(project, environment)
    pw = keyring.get_password(SERVICE_NAME, entry)
    if pw:
        console.print(f"[blue]Using password from keychain for {entry}")
    return pw


def delete_password(project: str, environment: str) -> None:
    """Remove a project password from the system keychain."""
    entry = _entry_name(project, environment)
    try:
        keyring.delete_password(SERVICE_NAME, entry)
        console.print(f"[green]Removed password from keychain for {entry}")
    except keyring.errors.PasswordDeleteError:
        pass


def save_token(token: str) -> None:
    """Store the GitHub token in the system keychain."""
    keyring.set_password(SERVICE_NAME, _TOKEN_ENTRY, token)
    console.print("[green]GitHub token saved to keychain")


def get_token() -> str | None:
    """Retrieve the GitHub token from the system keychain, or None."""
    token = keyring.get_password(SERVICE_NAME, _TOKEN_ENTRY)
    if token:
        console.print("[blue]Using GitHub token from keychain")
    return token


def delete_token() -> None:
    """Remove the GitHub token from the system keychain."""
    try:
        keyring.delete_password(SERVICE_NAME, _TOKEN_ENTRY)
        console.print("[green]Removed GitHub token from keychain")
    except keyring.errors.PasswordDeleteError:
        console.print("[yellow]No GitHub token found in keychain")
