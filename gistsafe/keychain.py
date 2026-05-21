"""System keychain integration — in-memory caching avoids multiple unlock prompts."""

import keyring

from .display import console

SERVICE_NAME = "gistsafe"
_TOKEN_ENTRY = "__github_token__"

_cache: dict[str, str | None] = {}
_primed = False


def _prime_cache() -> None:
    """Pre-load token from keychain to trigger a single macOS unlock prompt."""
    global _primed
    if _primed:
        return
    _primed = True
    try:
        token = keyring.get_password(SERVICE_NAME, _TOKEN_ENTRY)
        _cache[_TOKEN_ENTRY] = token
    except Exception:
        _cache[_TOKEN_ENTRY] = None


def _entry_name(project: str, environment: str) -> str:
    return f"{project}/{environment}"


def _read(entry: str) -> str | None:
    _prime_cache()
    if entry not in _cache:
        try:
            _cache[entry] = keyring.get_password(SERVICE_NAME, entry)
        except Exception:
            _cache[entry] = None
    return _cache[entry]


def save_password(project: str, environment: str, password: str) -> None:
    entry = _entry_name(project, environment)
    keyring.set_password(SERVICE_NAME, entry, password)
    _cache[entry] = password
    console.print(f"[green]Password saved to keychain for {entry}")


def get_password(project: str, environment: str) -> str | None:
    entry = _entry_name(project, environment)
    pw = _read(entry)
    if pw:
        console.print(f"[blue]Using password from keychain for {entry}")
    return pw


def delete_password(project: str, environment: str) -> None:
    entry = _entry_name(project, environment)
    try:
        keyring.delete_password(SERVICE_NAME, entry)
        console.print(f"[green]Removed password from keychain for {entry}")
    except keyring.errors.PasswordDeleteError:
        pass
    _cache.pop(entry, None)


def save_token(token: str) -> None:
    keyring.set_password(SERVICE_NAME, _TOKEN_ENTRY, token)
    _cache[_TOKEN_ENTRY] = token
    console.print("[green]GitHub token saved to keychain")


def get_token() -> str | None:
    token = _read(_TOKEN_ENTRY)
    if token:
        console.print("[blue]Using GitHub token from keychain")
    return token


def delete_token() -> None:
    try:
        keyring.delete_password(SERVICE_NAME, _TOKEN_ENTRY)
        console.print("[green]Removed GitHub token from keychain")
    except keyring.errors.PasswordDeleteError:
        console.print("[yellow]No GitHub token found in keychain")
    _cache.pop(_TOKEN_ENTRY, None)
