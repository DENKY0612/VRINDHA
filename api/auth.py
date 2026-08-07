"""JWT authentication and password storage for Vrindha."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, Optional
import json
import logging
import os
import secrets

import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class AuthModule:
    """Authenticate local users and issue signed, expiring JWTs."""

    def __init__(self, users_file: Optional[Path] = None, secret_key: Optional[str] = None):
        project_root = Path(__file__).resolve().parent.parent
        self.users_file = Path(users_file) if users_file else project_root / "database" / "users.json"
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self.algorithm = os.getenv("ALGORITHM", "HS256")
        self.expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
        self.secret_key = secret_key or os.getenv("SECRET_KEY")
        if not self.secret_key:
            # Safer than a repository-wide default. Tokens intentionally stop
            # working after restart until operators configure SECRET_KEY.
            self.secret_key = secrets.token_urlsafe(48)
            logger.warning("SECRET_KEY is not configured; using an ephemeral process key")
        elif len(self.secret_key) < 32:
            raise RuntimeError("SECRET_KEY must contain at least 32 characters")

        if not self.users_file.exists():
            self.users_file.write_text("{}\n", encoding="utf-8")
        self._provision_admin_from_environment()

    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    def load_users(self) -> Dict:
        try:
            data = json.loads(self.users_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            logger.exception("Could not load user database")
            return {}

    def _provision_admin_from_environment(self) -> None:
        username = os.getenv("ADMIN_USERNAME")
        password = os.getenv("ADMIN_PASSWORD")
        if not username and not password:
            return
        if not username or not password or len(password) < 12:
            raise RuntimeError("ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters are required")
        with self._lock:
            users = self.load_users()
            if username not in users:
                users[username] = {
                    "username": username,
                    "password_hash": self.hash_password(password),
                    "role": "admin",
                    "created": datetime.now(timezone.utc).isoformat(),
                }
                self.users_file.write_text(json.dumps(users, indent=2) + "\n", encoding="utf-8")
                logger.info("Provisioned administrator %s from environment", username)

    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        user = self.load_users().get(username)
        if not user or not self.verify_password(password, user.get("password_hash", "")):
            return None
        return user

    def create_access_token(self, data: Dict, expires_delta: Optional[timedelta] = None) -> str:
        payload = data.copy()
        now = datetime.now(timezone.utc)
        payload.update({
            "iat": now,
            "exp": now + (expires_delta or timedelta(minutes=self.expire_minutes)),
            "jti": secrets.token_hex(16),
        })
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload if payload.get("sub") else None
        except JWTError:
            return None


auth_module = AuthModule()
