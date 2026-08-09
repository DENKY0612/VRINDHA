"""JWT authentication and password storage for Vrindha."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, Optional
import json
import logging
import os
import re
import secrets
import tempfile

import bcrypt
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
SUPPORTED_ROLES = ("admin", "user")


class UserRegistrationError(Exception):
    """Base class for user-management validation failures."""


class InvalidUsernameError(UserRegistrationError):
    """Username violates the documented rules."""


class InvalidPasswordError(UserRegistrationError):
    """Password is weaker than the documented minimum."""


class InvalidRoleError(UserRegistrationError):
    """Role is not one of the supported roles."""


class DuplicateUserError(UserRegistrationError):
    """A user with the same (normalized) username already exists."""


class BootstrapClosedError(UserRegistrationError):
    """Public first-user registration is closed because users already exist."""


class AuthModule:
    """Authenticate local users and issue signed, expiring JWTs.

    Also provides secure user management: normalized usernames, bcrypt-only
    password hashing, supported roles, atomic first-user bootstrap, and atomic
    0600-permission writes to the JSON user store.
    """

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
            self._write_users({})
        self._provision_admin_from_environment()

    # ------------------------------------------------------------------ #
    # Password helpers (bcrypt only; never a plaintext or SHA fallback). #
    # ------------------------------------------------------------------ #
    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------ #
    # User store (JSON on disk, written atomically with 0600 bits).#
    # ------------------------------------------------------------ #
    def load_users(self) -> Dict:
        try:
            data = json.loads(self.users_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            logger.exception("Could not load user database")
            return {}

    def _write_users(self, users: Dict) -> None:
        """Write the user store through a temp file and replace it atomically.

        The final file is created with 0600 permissions so bcrypt hashes are
        not world-readable.
        """
        directory = self.users_file.parent
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(directory), prefix=".users-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(users, handle, indent=2)
                handle.write("\n")
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.users_file)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------ #
    # User management                                                    #
    # ------------------------------------------------------------------ #
    @staticmethod
    def normalize_username(username: str) -> str:
        """Lowercase and trim a username for canonical storage/lookup."""
        return username.strip().lower() if isinstance(username, str) else username

    @staticmethod
    def _validate_username(username: str) -> None:
        if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
            raise InvalidUsernameError(
                "Username must be 3-64 characters, start with a letter or number, "
                "and contain only letters, numbers, '.', '_', or '-'"
            )

    @staticmethod
    def _validate_password(password: str) -> None:
        if not isinstance(password, str) or len(password) < 12:
            raise InvalidPasswordError("Password must be at least 12 characters")

    @staticmethod
    def _validate_role(role: str) -> None:
        if role not in SUPPORTED_ROLES:
            raise InvalidRoleError("Role must be 'admin' or 'user'")

    def has_users(self) -> bool:
        return bool(self.load_users())

    def create_user(self, username: str, password: str, role: str = "user", require_empty: bool = False) -> Dict:
        """Create a user and return its public record (never the password hash).

        ``require_empty`` is used for first-user bootstrap: it atomically
        guarantees that exactly one administrator is created even when two
        requests race.
        """
        name = self.normalize_username(username)
        self._validate_username(name)
        self._validate_password(password)
        self._validate_role(role)
        with self._lock:
            users = self.load_users()
            if require_empty and users:
                raise BootstrapClosedError("Public registration is closed; the first administrator already exists")
            if require_empty:
                # The very first account is always the administrator, regardless
                # of the role requested by the caller.
                role = "admin"
            if name in users:
                raise DuplicateUserError(f"Username '{name}' already exists")
            record = {
                "username": name,
                "password_hash": self.hash_password(password),
                "role": role,
                "active": True,
                "created": datetime.now(timezone.utc).isoformat(),
            }
            users[name] = record
            self._write_users(users)
            return {key: value for key, value in record.items() if key != "password_hash"}

    def _provision_admin_from_environment(self) -> None:
        username = os.getenv("ADMIN_USERNAME")
        password = os.getenv("ADMIN_PASSWORD")
        if not username and not password:
            return
        if not username or not password or len(password) < 12:
            raise RuntimeError("ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters are required")
        with self._lock:
            users = self.load_users()
            name = self.normalize_username(username)
            self._validate_username(name)
            if name not in users:
                users[name] = {
                    "username": name,
                    "password_hash": self.hash_password(password),
                    "role": "admin",
                    "active": True,
                    "created": datetime.now(timezone.utc).isoformat(),
                }
                self._write_users(users)
                logger.info("Provisioned administrator %s from environment", name)

    # ------------------------------------------------------------------ #
    # Authentication                                                      #
    # ------------------------------------------------------------------ #
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        user = self.load_users().get(self.normalize_username(username))
        if not user:
            return None
        if not user.get("active", True):
            return None
        if not self.verify_password(password, user.get("password_hash", "")):
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
