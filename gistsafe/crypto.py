"""Encryption and key derivation using PBKDF2 + Fernet.

All secrets are encrypted client-side before storage. The encryption
password never leaves the user's machine.
"""

import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import PBKDF2_ITERATIONS, SALT_LENGTH


def generate_key(password: str, salt: bytes | None = None) -> tuple[Fernet, bytes]:
    """Generate a Fernet key from a password using PBKDF2HMAC-SHA256.

    Args:
        password: The user-provided encryption password.
        salt: Optional salt bytes. If None, a new 16-byte salt is generated.

    Returns:
        A tuple of (Fernet instance, salt bytes used).
    """
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key), salt


def encrypt_value(value: str, password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt a string value using Fernet symmetric encryption.

    Args:
        value: The plaintext value to encrypt.
        password: The encryption password.
        salt: Optional salt. Generated if not provided.

    Returns:
        A tuple of (encrypted_bytes, salt_bytes).
    """
    f, salt = generate_key(password, salt)
    encrypted_value = f.encrypt(value.encode())
    return encrypted_value, salt


def decrypt_value(encrypted_value: bytes, password: str, salt: bytes) -> str:
    """Decrypt a Fernet-encrypted value.

    Args:
        encrypted_value: The encrypted bytes.
        password: The encryption password.
        salt: The salt used during encryption.

    Returns:
        The decrypted plaintext string.

    Raises:
        cryptography.fernet.InvalidToken: If the password is incorrect.
    """
    f, _ = generate_key(password, salt)
    return f.decrypt(encrypted_value).decode()


def encrypt_key(key: str, password: str, salt: bytes) -> str:
    """Encrypt a secret key name for obfuscated storage.

    Args:
        key: The plaintext key name.
        password: The encryption password.
        salt: The salt to use.

    Returns:
        Base64-encoded encrypted key string.
    """
    f, _ = generate_key(password, salt)
    encrypted_key = f.encrypt(key.encode())
    return base64.b64encode(encrypted_key).decode()


def decrypt_key(encrypted_key: str, password: str, salt: bytes) -> str:
    """Decrypt an obfuscated key name.

    Args:
        encrypted_key: The base64-encoded encrypted key.
        password: The encryption password.
        salt: The salt used during encryption.

    Returns:
        The original plaintext key name.
    """
    f, _ = generate_key(password, salt)
    return f.decrypt(base64.b64decode(encrypted_key)).decode()
