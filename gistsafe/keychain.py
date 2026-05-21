"""System keychain integration — uses native macOS security CLI to avoid
multiple unlock prompts, falls back to keyring on other platforms."""

import subprocess
import sys

import keyring

from .display import console

SERVICE_NAME = "gistsafe"
_TOKEN_ENTRY = "__github_token__"

_cache: dict[str, str | None] = {}
_primed = False

IS_MACOS = sys.platform == "darwin"


def _security_read(account: str) -> str | None:
    result = subprocess.run(
        ["security", "find-generic-password", "-s", SERVICE_NAME,
         "-a", account, "-w"],
        capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _security_write(account: str, value: str) -> None:
    subprocess.run(
        ["security", "add-generic-password", "-s", SERVICE_NAME,
         "-a", account, "-w", value, "-U"],
        capture_output=True,
    )


def _security_delete(account: str) -> None:
    subprocess.run(
        ["security", "delete-generic-password", "-s", SERVICE_NAME,
         "-a", account],
        capture_output=True,
    )


def _prime_cache() -> None:
    global _primed
    if _primed:
        return
    _primed = True
    if IS_MACOS:
        _cache[_TOKEN_ENTRY] = _security_read(_TOKEN_ENTRY)
    else:
        try:
            _cache[_TOKEN_ENTRY] = keyring.get_password(SERVICE_NAME, _TOKEN_ENTRY)
        except Exception:
            _cache[_TOKEN_ENTRY] = None


def _entry_name(project: str, environment: str) -> str:
    return f"{project}/{environment}"


def _read(entry: str) -> str | None:
    _prime_cache()
    if entry not in _cache:
        if IS_MACOS:
            _cache[entry] = _security_read(entry)
        else:
            try:
                _cache[entry] = keyring.get_password(SERVICE_NAME, entry)
            except Exception:
                _cache[entry] = None
    return _cache[entry]


def save_password(project: str, environment: str, password: str) -> None:
    entry = _entry_name(project, environment)
    if IS_MACOS:
        _security_delete(entry)
        _security_write(entry, password)
    else:
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
    if IS_MACOS:
        _security_delete(entry)
    else:
        try:
            keyring.delete_password(SERVICE_NAME, entry)
        except keyring.errors.PasswordDeleteError:
            pass
    _cache.pop(entry, None)
    console.print(f"[green]Removed password from keychain for {entry}")


def save_token(token: str) -> None:
    if IS_MACOS:
        _security_delete(_TOKEN_ENTRY)
        _security_write(_TOKEN_ENTRY, token)
    else:
        keyring.set_password(SERVICE_NAME, _TOKEN_ENTRY, token)
    _cache[_TOKEN_ENTRY] = token
    console.print("[green]GitHub token saved to keychain")


def get_token() -> str | None:
    token = _read(_TOKEN_ENTRY)
    if token:
        console.print("[blue]Using GitHub token from keychain")
    return token


def delete_token() -> None:
    if IS_MACOS:
        _security_delete(_TOKEN_ENTRY)
    else:
        try:
            keyring.delete_password(SERVICE_NAME, _TOKEN_ENTRY)
        except keyring.errors.PasswordDeleteError:
            pass
    _cache.pop(_TOKEN_ENTRY, None)
    console.print("[green]Removed GitHub token from keychain")
