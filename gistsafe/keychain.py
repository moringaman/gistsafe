"""System keychain integration — native Security framework via ctypes.

Zero subprocesses on macOS = one keychain prompt total. Falls back to
keyring library on Linux/Windows.
"""

import ctypes
import ctypes.util
import sys

from .display import console

SERVICE = "gistsafe"
_TOKEN_ACCT = "__github_token__"

_cache: dict[str, str | None] = {}
_primed = False

IS_MACOS = sys.platform == "darwin"

if IS_MACOS:
    _sec = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Security"))
    _cf = ctypes.cdll.LoadLibrary(ctypes.util.find_library("CoreFoundation"))

    _utf8 = 0x08000100

    def _cfstr(s: str):
        return _cf.CFStringCreateWithCString(None, s.encode(), _utf8)

    def _cfstr_value(cf) -> str:
        buf = ctypes.create_string_buffer(1024)
        if _cf.CFStringGetCString(cf, buf, 1024, _utf8):
            return buf.value.decode()
        return ""

    _kTrue = ctypes.c_void_p.in_dll(_cf, "kCFBooleanTrue")
    _kFalse = ctypes.c_void_p.in_dll(_cf, "kCFBooleanFalse")
    _kDictKeyCB = ctypes.c_void_p.in_dll(_cf, "kCFTypeDictionaryKeyCallBacks")
    _kDictValCB = ctypes.c_void_p.in_dll(_cf, "kCFTypeDictionaryValueCallBacks")

    _cf_class = _cfstr("class")
    _cf_genp = _cfstr("genp")
    _cf_svce = _cfstr("svce")
    _cf_acct = _cfstr("acct")
    _cf_vdat = _cfstr("v_Data")
    _cf_rdat = _cfstr("r_Data")
    _cf_mlim = _cfstr("m_Limit")
    _cf_ml1 = _cfstr("m_LimitOne")
    _cf_sync = _cfstr("sync")
    _cf_syn = _cfstr("synchronizable")
    _cf_svc_val = _cfstr(SERVICE)

    _errItemNotFound = -25300

    def _keychain_read(account: str) -> str | None:
        acct = _cfstr(account)
        keys = (_cf_class, _cf_svce, _cf_acct, _cf_rdat, _cf_mlim, _cf_sync)
        vals = (_cf_genp, _cf_svc_val, acct, _kTrue, _cf_ml1, _cf_syn)
        query = _cf.CFDictionaryCreate(None,
            (ctypes.c_void_p * 6)(*keys),
            (ctypes.c_void_p * 6)(*vals), 6, _kDictKeyCB, _kDictValCB)
        result = ctypes.c_void_p()
        status = _sec.SecItemCopyMatching(query, ctypes.byref(result))
        _cf.CFRelease(query)
        _cf.CFRelease(acct)
        if status != 0 or not result:
            return None
        data = _cf.CFDictionaryGetValue(result, _cf_vdat)
        pw = None
        if data:
            length = _cf.CFDataGetLength(data)
            if length > 0:
                pw = ctypes.string_at(_cf.CFDataGetBytePtr(data), length).decode()
        _cf.CFRelease(result)
        return pw

    def _keychain_write(account: str, password: str) -> None:
        _keychain_delete(account)
        acct = _cfstr(account)
        pw_bytes = password.encode()
        pw_cf = _cf.CFDataCreate(None, pw_bytes, len(pw_bytes))
        attrs = _cf.CFDictionaryCreate(None,
            (ctypes.c_void_p * 3)(_cf_class, _cf_svce, _cf_acct),
            (ctypes.c_void_p * 3)(_cf_genp, _cf_svc_val, acct),
            3, _kDictKeyCB, _kDictValCB)
        add = _cf.CFDictionaryCreate(None,
            (ctypes.c_void_p * 1)(_cf_vdat,),
            (ctypes.c_void_p * 1)(pw_cf, attrs),
            1, _kDictKeyCB, _kDictValCB)
        _sec.SecItemAdd(add, None)
        _cf.CFRelease(attrs)
        _cf.CFRelease(add)
        _cf.CFRelease(pw_cf)
        _cf.CFRelease(acct)

    def _keychain_delete(account: str) -> None:
        acct = _cfstr(account)
        query = _cf.CFDictionaryCreate(None,
            (ctypes.c_void_p * 3)(_cf_class, _cf_svce, _cf_acct),
            (ctypes.c_void_p * 3)(_cf_genp, _cf_svc_val, acct),
            3, _kDictKeyCB, _kDictValCB)
        _sec.SecItemDelete(query)
        _cf.CFRelease(query)
        _cf.CFRelease(acct)

else:
    import keyring


def _prime_cache() -> None:
    global _primed
    if _primed:
        return
    _primed = True
    if IS_MACOS:
        _cache[_TOKEN_ACCT] = _keychain_read(_TOKEN_ACCT)
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
            _cache[account] = _keychain_read(account)
        else:
            try:
                _cache[account] = keyring.get_password(SERVICE, account)
            except Exception:
                _cache[account] = None
    return _cache[account]


def save_password(project: str, environment: str, password: str) -> None:
    entry = _entry_name(project, environment)
    if IS_MACOS:
        _keychain_write(entry, password)
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
        _keychain_delete(entry)
    else:
        try:
            keyring.delete_password(SERVICE, entry)
        except keyring.errors.PasswordDeleteError:
            pass
    _cache.pop(entry, None)
    console.print(f"[green]Removed password from keychain for {entry}")


def save_token(token: str) -> None:
    if IS_MACOS:
        _keychain_write(_TOKEN_ACCT, token)
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
        _keychain_delete(_TOKEN_ACCT)
    else:
        try:
            keyring.delete_password(SERVICE, _TOKEN_ACCT)
        except keyring.errors.PasswordDeleteError:
            pass
    _cache.pop(_TOKEN_ACCT, None)
    console.print("[green]Removed GitHub token from keychain")
