from __future__ import annotations

import base64
import hmac
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import PBKDF2_ITERATIONS


class SecurityManager:
    def __init__(self, salt_path: Path) -> None:
        self.salt_path = salt_path
        self.salt_path.parent.mkdir(parents=True, exist_ok=True)
        self._salt = self._load_or_create_salt()

    @staticmethod
    def _set_restrictive_permissions(path: Path, mode: int) -> None:
        try:
            os.chmod(path, mode)
        except Exception:
            pass

    def _load_or_create_salt(self) -> bytes:
        if self.salt_path.exists():
            salt = self.salt_path.read_bytes()
            self._set_restrictive_permissions(self.salt_path, 0o600)
            return salt
        salt = os.urandom(16)
        self.salt_path.write_bytes(salt)
        self._set_restrictive_permissions(self.salt_path, 0o600)
        return salt

    def _stable_hmac(self, scope: str, value: str) -> str:
        return hmac.new(
            self._salt,
            f'buddy-radar::{scope}::{value}'.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

    def visibility_hash(self, code: str) -> str:
        return self._stable_hmac('visibility', code)

    def username_key(self, username: str) -> str:
        normalized = ' '.join(username.strip().split()).casefold()
        return self._stable_hmac('username', normalized)

    def derive_fernet(self, code: str) -> Fernet:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(code.encode('utf-8')))
        return Fernet(key)

    def encrypt_text(self, text: str, code: str) -> str:
        return self.derive_fernet(code).encrypt(text.encode('utf-8')).decode('utf-8')

    def decrypt_text(self, token: str, code: str) -> str:
        return self.derive_fernet(code).decrypt(token.encode('utf-8')).decode('utf-8')
