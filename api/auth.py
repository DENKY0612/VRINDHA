"""
Authentication System Prompt - Per START UP.pdf
Build secure authentication system
Features: JWT authentication, login endpoint, token verification
Security: Password hashing (bcrypt / pbkdf2), token expiration
Endpoints: POST /login, Protected routes
"""
from datetime import datetime, timedelta
from typing import Dict, Optional
import hashlib
import secrets
import json
from pathlib import Path

# Try to import JWT libraries, fallback to simple implementation
try:
    from jose import jwt, JWTError
    JOSE_AVAILABLE = True
    SECRET_KEY = "vrindha-super-secret-jwt-key-change-in-production-2026"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60
except ImportError:
    JOSE_AVAILABLE = False
    SECRET_KEY = "vrindha-super-secret"

class AuthModule:
    def __init__(self):
        self.users_file = Path("database/users.json")
        if not self.users_file.parent.exists():
            alt = Path("vrindha/database/users.json")
            if alt.parent.exists():
                self.users_file = alt
            else:
                self.users_file = Path("/home/user/vrindha/database/users.json")
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.users_file.exists():
            # Create default admin user: admin/admin123 hashed
            default_users = {
                "admin": {
                    "username": "admin",
                    "password_hash": self.hash_password("admin123"),
                    "role": "admin",
                    "created": datetime.now().isoformat()
                }
            }
            self.users_file.write_text(json.dumps(default_users, indent=2))
    
    def hash_password(self, password: str) -> str:
        # Try bcrypt if available, else use sha256 with salt for MVP
        try:
            import bcrypt
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        except:
            # Fallback pbkdf2-like sha256
            salt = "vrindha-salt"
            return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def verify_password(self, plain: str, hashed: str) -> bool:
        try:
            import bcrypt
            return bcrypt.checkpw(plain.encode(), hashed.encode())
        except:
            salt = "vrindha-salt"
            return hashlib.sha256((plain + salt).encode()).hexdigest() == hashed
    
    def load_users(self) -> Dict:
        try:
            return json.loads(self.users_file.read_text())
        except:
            return {}
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        users = self.load_users()
        user = users.get(username)
        if not user:
            return None
        if not self.verify_password(password, user.get("password_hash","")):
            return None
        return user
    
    def create_access_token(self, data: Dict, expires_delta: Optional[timedelta] = None) -> str:
        if JOSE_AVAILABLE:
            to_encode = data.copy()
            expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
            to_encode.update({"exp": expire})
            encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
            return encoded_jwt
        else:
            # Simple fallback token (not secure, but for MVP)
            token = f"{data.get('sub')}:{secrets.token_hex(16)}:{datetime.now().timestamp()}"
            return token
    
    def verify_token(self, token: str) -> Optional[Dict]:
        if JOSE_AVAILABLE:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                return payload
            except JWTError:
                return None
        else:
            # Simple parse
            try:
                parts = token.split(":")
                username = parts[0]
                users = self.load_users()
                if username in users:
                    return {"sub": username}
                return None
            except:
                return None

auth_module = AuthModule()
