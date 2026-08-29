import os
import json
import urllib.request
import urllib.parse

def get_supabase_config():
    """Load Supabase configuration from environment variables, config.json, or .env."""
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = os.environ.get("SUPABASE_KEY", os.environ.get("SUPABASE_SERVICE_ROLE_KEY", os.environ.get("SUPABASE_ANON_KEY", ""))).strip()

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Check config.json fallback
    config_file = os.path.join(root_dir, "config.json")
    if not (url and key) and os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                url = url or data.get("SUPABASE_URL", "").strip().rstrip("/")
                key = key or data.get("SUPABASE_KEY", data.get("SUPABASE_ANON_KEY", "")).strip()
        except Exception:
            pass

    # 2. Check .env fallback
    env_file = os.path.join(root_dir, ".env")
    if not (url and key) and os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k == "SUPABASE_URL" and not url:
                            url = v.rstrip("/")
                        elif k in ["SUPABASE_KEY", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"] and not key:
                            key = v
        except Exception:
            pass

    return url, key

def is_supabase_configured() -> bool:
    """Check if Supabase credentials are provided."""
    url, key = get_supabase_config()
    return bool(url and key)

def _supabase_request(endpoint: str, method: str = "GET", payload: dict = None, query_params: str = None):
    """Execute authenticated HTTP request against Supabase PostgREST API."""
    url_base, api_key = get_supabase_config()
    if not (url_base and api_key):
        return None

    url = f"{url_base}/rest/v1/{endpoint}"
    if query_params:
        url = f"{url}?{query_params}"

    headers = {
        "apikey": api_key,
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    data = json.dumps(payload).encode("utf-8") if payload is not None else None

    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            res_body = response.read().decode("utf-8")
            return json.loads(res_body) if res_body else []
    except Exception as e:
        print(f"[Supabase Error] {method} {url}: {str(e)}")
        return None

# -------------------------------------------------------------------
# USER CRUD OPERATIONS
# -------------------------------------------------------------------
def get_user_by_identifier(identifier: str):
    """Find user by username or email (case-insensitive) in Supabase."""
    if not is_supabase_configured():
        return None

    ident = identifier.strip().lower()
    query = f"or=(username.ilike.{urllib.parse.quote(ident)},email.ilike.{urllib.parse.quote(ident)})"
    results = _supabase_request("users", method="GET", query_params=query)
    if results and isinstance(results, list) and len(results) > 0:
        return results[0]
    return None

def get_user_by_id(user_id: str):
    """Fetch user by primary key ID in Supabase."""
    if not is_supabase_configured():
        return None

    query = f"id=eq.{urllib.parse.quote(user_id)}"
    results = _supabase_request("users", method="GET", query_params=query)
    if results and isinstance(results, list) and len(results) > 0:
        return results[0]
    return None

def create_user(user_dict: dict):
    """Insert a new user into Supabase."""
    if not is_supabase_configured():
        return None

    res = _supabase_request("users", method="POST", payload=user_dict)
    if res and isinstance(res, list) and len(res) > 0:
        return res[0]
    return None

def update_user(user_id: str, updates: dict):
    """Update fields for a user in Supabase."""
    if not is_supabase_configured():
        return None

    query = f"id=eq.{urllib.parse.quote(user_id)}"
    res = _supabase_request("users", method="PATCH", payload=updates, query_params=query)
    if res and isinstance(res, list) and len(res) > 0:
        return res[0]
    return None
