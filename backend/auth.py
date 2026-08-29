import os
import json
import time
import hmac
import hashlib
import base64
import uuid

from backend.supabase_db import (
    is_supabase_configured,
    get_user_by_identifier as supabase_get_user_by_identifier,
    get_user_by_id as supabase_get_user_by_id,
    create_user as supabase_create_user,
    update_user as supabase_update_user
)

# Secret key for JWT signing - can be configured via environment variable
JWT_SECRET = os.environ.get("JWT_SECRET", "vanguard_student_security_jwt_secret_2026")
TOKEN_EXPIRY_SECONDS = 30 * 24 * 3600  # 30 days persistent session

def get_storage_path():
    """Determine writable file path for users storage."""
    local_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    try:
        if not os.path.exists(local_dir):
            os.makedirs(local_dir, exist_ok=True)
        test_file = os.path.join(local_dir, ".writable_test")
        with open(test_file, "w") as f:
            f.write("ok")
        if os.path.exists(test_file):
            os.remove(test_file)
        return os.path.join(local_dir, "users.json")
    except Exception:
        # Fallback to /tmp on serverless environments like Vercel
        return "/tmp/vanguard_users.json"

USERS_FILE = get_storage_path()

def hash_password(password: str, salt: bytes = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with random salt."""
    if salt is None:
        salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"{salt.hex()}:{pw_hash.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored salt:hash string."""
    try:
        parts = stored_hash.split(":")
        if len(parts) != 2:
            return False
        salt = bytes.fromhex(parts[0])
        expected_hash = parts[1]
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(pw_hash.hex(), expected_hash)
    except Exception:
        return False

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("utf-8"))

def create_jwt(payload: dict) -> str:
    """Generate a standard HS256 JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    header_b64 = b64url_encode(header_json)
    payload_b64 = b64url_encode(payload_json)

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"

def verify_jwt(token: str):
    """Verify HS256 JWT token and return decoded payload if valid."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return False, "Invalid token format"

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        provided_sig = b64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, provided_sig):
            return False, "Signature verification failed"

        payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
        if "exp" in payload and time.time() > payload["exp"]:
            return False, "Token expired"

        return True, payload
    except Exception as e:
        return False, f"Token verification error: {str(e)}"

# Default Student / Developer Accounts
DEFAULT_USERS = {
    "usr_student_01": {
        "id": "usr_student_01",
        "username": "student",
        "email": "student@college.edu",
        "password_hash": hash_password("student123"),
        "full_name": "Student Developer",
        "college": "Engineering & Technology Institute",
        "role": "Student Web Developer",
        "created_at": "2026-01-01 00:00:00"
    }
}

# Runtime memory cache for local JSON
_users_cache = None

def load_local_users():
    """Load users from storage with in-memory fallback."""
    global _users_cache
    if _users_cache is not None:
        return _users_cache

    loaded = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                raw_users = json.load(f)
                for uid, u in raw_users.items():
                    loaded[uid] = {
                        "id": u.get("id", uid),
                        "username": u.get("username", ""),
                        "email": u.get("email", ""),
                        "password_hash": u.get("password_hash", ""),
                        "full_name": u.get("full_name", u.get("username", "")),
                        "college": u.get("college", u.get("organization", "University / College")),
                        "role": u.get("role", "Student Developer"),
                        "created_at": u.get("created_at", time.strftime("%Y-%m-%d %H:%M:%S"))
                    }
        except Exception:
            loaded = {}

    for k, v in DEFAULT_USERS.items():
        if k not in loaded:
            loaded[k] = v

    _users_cache = loaded
    return _users_cache

def save_local_users(users):
    """Persist users to local storage."""
    global _users_cache
    _users_cache = users
    try:
        storage_path = USERS_FILE
        parent = os.path.dirname(storage_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(storage_path, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        return True
    except Exception:
        return True

def sanitize_user(user: dict) -> dict:
    """Return clean user dict without password hash or enterprise clutter."""
    if not user:
        return {}
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email"),
        "full_name": user.get("full_name", user.get("username")),
        "college": user.get("college", user.get("organization", "College / University")),
        "role": user.get("role", "Student Developer"),
        "created_at": user.get("created_at")
    }

def find_user_by_identifier(identifier: str):
    """Find user by username or email (case-insensitive) in Supabase or local JSON."""
    if is_supabase_configured():
        user = supabase_get_user_by_identifier(identifier)
        if user:
            return user

    # Fallback to local JSON store
    users = load_local_users()
    ident = identifier.strip().lower()
    for u in users.values():
        if u.get("username", "").lower() == ident or u.get("email", "").lower() == ident:
            return u
    return None

def find_user_by_id(user_id: str):
    """Find user by unique ID in Supabase or local JSON."""
    if is_supabase_configured():
        user = supabase_get_user_by_id(user_id)
        if user:
            return user

    users = load_local_users()
    return users.get(user_id)

def authenticate_user(identifier: str, password: str):
    """Authenticate user credentials and return JWT token + clean student profile."""
    if not identifier or not password:
        return {"success": False, "error": "Username/Email and Password are required"}

    user = find_user_by_identifier(identifier)
    if not user:
        return {"success": False, "error": "Invalid username/email or password"}

    if not verify_password(password, user.get("password_hash", "")):
        return {"success": False, "error": "Invalid username/email or password"}

    # Issue JWT token
    payload = {
        "user_id": user["id"],
        "username": user.get("username"),
        "email": user.get("email"),
        "role": user.get("role"),
        "college": user.get("college"),
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS,
        "iat": int(time.time())
    }
    token = create_jwt(payload)

    return {
        "success": True,
        "token": token,
        "user": sanitize_user(user)
    }

def register_user(username: str, email: str, password: str, full_name: str = None, role: str = None, college: str = None):
    """Register a new student/developer user account in Supabase or local JSON."""
    username = username.strip()
    email = email.strip().lower()
    
    if not username or len(username) < 3:
        return {"success": False, "error": "Username must be at least 3 characters"}
    if not email or "@" not in email or "." not in email:
        return {"success": False, "error": "Valid email address is required"}
    if not password or len(password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters"}

    # Check duplicate
    existing = find_user_by_identifier(username) or find_user_by_identifier(email)
    if existing:
        if existing.get("username", "").lower() == username.lower():
            return {"success": False, "error": "Username is already taken"}
        return {"success": False, "error": "Email address is already registered"}

    user_id = f"usr_{uuid.uuid4().hex[:10]}"
    new_user = {
        "id": user_id,
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "full_name": full_name.strip() if full_name else username,
        "college": college.strip() if college else "College / University",
        "role": role.strip() if role else "Student Developer",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    if is_supabase_configured():
        created = supabase_create_user(new_user)
        if created:
            new_user = created

    # Always save locally as well
    local_users = load_local_users()
    local_users[user_id] = new_user
    save_local_users(local_users)

    # Issue JWT token
    payload = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "role": new_user.get("role"),
        "college": new_user.get("college"),
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS,
        "iat": int(time.time())
    }
    token = create_jwt(payload)

    return {
        "success": True,
        "token": token,
        "user": sanitize_user(new_user)
    }

def get_current_user_from_token(token: str):
    """Retrieve clean student user object given a valid JWT token."""
    valid, result = verify_jwt(token)
    if not valid:
        return False, result

    user_id = result.get("user_id")
    user = find_user_by_id(user_id)
    if not user:
        return False, "User not found"

    return True, sanitize_user(user)

def update_user_profile(user_id: str, updates: dict):
    """Update student profile fields in Supabase or local JSON."""
    user = find_user_by_id(user_id)
    if not user:
        return {"success": False, "error": "User record not found"}

    cleaned_updates = {}
    if "full_name" in updates and updates["full_name"]:
        cleaned_updates["full_name"] = str(updates["full_name"]).strip()
    if "role" in updates and updates["role"]:
        cleaned_updates["role"] = str(updates["role"]).strip()
    if "college" in updates and updates["college"]:
        cleaned_updates["college"] = str(updates["college"]).strip()
    elif "organization" in updates and updates["organization"]:
        cleaned_updates["college"] = str(updates["organization"]).strip()

    if "email" in updates and updates["email"]:
        new_email = str(updates["email"]).strip().lower()
        existing = find_user_by_identifier(new_email)
        if existing and existing.get("id") != user_id:
            return {"success": False, "error": "Email address is already in use"}
        cleaned_updates["email"] = new_email

    if is_supabase_configured():
        supabase_update_user(user_id, cleaned_updates)

    # Update local copy
    local_users = load_local_users()
    if user_id in local_users:
        local_users[user_id].update(cleaned_updates)
        save_local_users(local_users)
        user = local_users[user_id]
    else:
        user.update(cleaned_updates)

    return {"success": True, "user": sanitize_user(user)}

def change_user_password(user_id: str, old_password: str, new_password: str):
    """Update password for an authenticated user."""
    if not new_password or len(new_password) < 6:
        return {"success": False, "error": "New password must be at least 6 characters"}

    user = find_user_by_id(user_id)
    if not user:
        return {"success": False, "error": "User record not found"}

    if not verify_password(old_password, user.get("password_hash", "")):
        return {"success": False, "error": "Current password is incorrect"}

    new_hash = hash_password(new_password)
    if is_supabase_configured():
        supabase_update_user(user_id, {"password_hash": new_hash})

    local_users = load_local_users()
    if user_id in local_users:
        local_users[user_id]["password_hash"] = new_hash
        save_local_users(local_users)

    return {"success": True, "message": "Password updated successfully"}

change_password = change_user_password
