"""System keychain integration for storing project encryption passwords."""

import keyring

from .display import console

SERVICE_NAME = "gistsafe"


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
