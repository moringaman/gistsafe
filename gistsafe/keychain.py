"""System keychain integration.

On macOS, lists and reads ALL gistsafe entries in a single subprocess —
one keychain unlock prompt per session. Falls back to keyring elsewhere.
"""

import subprocess
import sys

from .display import console

SERVICE = "gistsafe"
_TOKEN_ACCT = "__github_token__"

_cache: dict[str, str | None] = {}
_primed = False

IS_MACOS = sys.platform == "darwin"

if not IS_MACOS:
    import keyring


def _macos_load_all() -> dict[str, str | None]:
    """One subprocess: list all accounts AND read all passwords."""
    script = (
        f"for acct in $(security find-generic-password -s {SERVICE} 2>/dev/null"
        f" | grep '\"acct\"' | cut -d'\"' -f4); do "
        f'echo "GS:$acct"; '
        f"security find-generic-password -s {SERVICE} -a \"$acct\" -w 2>/dev/null"
        f' || echo "__NONE__"; '
        f'echo "GE:$acct"; '
        f"done"
    )
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    output: dict[str, str | None] = {}
    current = None
    for line in result.stdout.splitlines():
        if line.startswith("GS:"):
            current = line[3:]
        elif line.startswith("GE:"):
            current = None
        elif current is not None:
            output[current] = None if line == "__NONE__" else line
    return output


def _macos_write(account: str, value: str) -> None:
    _macos_delete(account)
    subprocess.run(
        ["security", "add-generic-password", "-s", SERVICE,
         "-a", account, "-w", value, "-U"],
        capture_output=True,
    )


def _macos_delete(account: str) -> None:
    subprocess.run(
        ["security", "delete-generic-password", "-s", SERVICE, "-a", account],
        capture_output=True,
    )


def _prime_cache() -> None:
    global _primed
    if _primed:
        return
    _primed = True
    if IS_MACOS:
        _cache.update(_macos_load_all())
    else:
        try:
            _cache[_TOKEN_ACCT] = keyring.get_password(SERVICE, _TOKEN_ACCT)
        except Exception:
            _cache[_TOKEN_ACCT] = None


def _entry_name(project: str, environment: str) -> str:
    return f"{project}/{environment}"


def _read(account: str) -> str | None:
    _prime_cache()
    if account not in _cache:
        if IS_MACOS:
            result = subprocess.run(
                ["security", "find-generic-password", "-s", SERVICE,
                 "-a", account, "-w"],
                capture_output=True, text=True,
            )
            _cache[account] = result.stdout.strip() if result.returncode == 0 else None
        else:
            try:
                _cache[account] = keyring.get_password(SERVICE, account)
            except Exception:
                _cache[account] = None
    return _cache[account]


def save_password(project: str, environment: str, password: str) -> None:
    entry = _entry_name(project, environment)
    if IS_MACOS:
        _macos_write(entry, password)
    else:
        keyring.set_password(SERVICE, entry, password)
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
        _macos_delete(entry)
    else:
        try:
            keyring.delete_password(SERVICE, entry)
        except keyring.errors.PasswordDeleteError:
            pass
    _cache.pop(entry, None)
    console.print(f"[green]Removed password from keychain for {entry}")


def save_token(token: str) -> None:
    if IS_MACOS:
        _macos_write(_TOKEN_ACCT, token)
    else:
        keyring.set_password(SERVICE, _TOKEN_ACCT, token)
    _cache[_TOKEN_ACCT] = token
    console.print("[green]GitHub token saved to keychain")


def get_token() -> str | None:
    token = _read(_TOKEN_ACCT)
    if token:
        console.print("[blue]Using GitHub token from keychain")
    return token


def delete_token() -> None:
    if IS_MACOS:
        _macos_delete(_TOKEN_ACCT)
    else:
        try:
            keyring.delete_password(SERVICE, _TOKEN_ACCT)
        except keyring.errors.PasswordDeleteError:
            pass
    _cache.pop(_TOKEN_ACCT, None)
    console.print("[green]Removed GitHub token from keychain")
