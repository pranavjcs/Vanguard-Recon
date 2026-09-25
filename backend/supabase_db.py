import os
import json
import urllib.request
import urllib.parse
import urllib.error

def get_supabase_config():
    """Load Supabase configuration from environment variables, config.json, or .env.
    Supports standard Supabase keys as well as official Vercel integration variables
    (e.g. NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY).
    """
    url_aliases = [
        "SUPABASE_URL", "supabase_url",
        "NEXT_PUBLIC_SUPABASE_URL", "next_public_supabase_url",
        "VITE_SUPABASE_URL"
    ]
    key_aliases = [
        "SUPABASE_KEY", "supabase_key",
        "SUPABASE_SERVICE_ROLE_KEY", "supabase_service_role_key",
        "SUPABASE_ANON_KEY", "supabase_anon_key",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY", "next_public_supabase_anon_key",
        "VITE_SUPABASE_ANON_KEY"
    ]

    url = ""
    for k in url_aliases:
        val = os.environ.get(k, "").strip()
        if val:
            url = val.rstrip("/")
            break

    key = ""
    for k in key_aliases:
        val = os.environ.get(k, "").strip()
        if val:
            key = val
            break

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Check config.json fallback
    config_file = os.path.join(root_dir, "config.json")
    if not (url and key) and os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not url:
                    for k in url_aliases:
                        if data.get(k):
                            url = str(data[k]).strip().rstrip("/")
                            break
                if not key:
                    for k in key_aliases:
                        if data.get(k):
                            key = str(data[k]).strip()
                            break
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
                        if not url and k in url_aliases:
                            url = v.rstrip("/")
                        elif not key and k in key_aliases:
                            key = v
        except Exception:
            pass

    return url, key

def is_supabase_configured() -> bool:
    """Check if Supabase credentials are provided."""
    url, key = get_supabase_config()
    return bool(url and key)

def check_supabase_status():
    """Diagnose Supabase connection and public.users table status."""
    url, key = get_supabase_config()
    if not (url and key):
        return False, "CREDENTIALS_MISSING", "SUPABASE_URL or SUPABASE_KEY is missing."

    test_url = f"{url}/rest/v1/users?limit=1"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    req = urllib.request.Request(test_url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return True, "READY", "Supabase connected and 'public.users' table is active."
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        if e.code == 404 or "42P01" in err_body or "does not exist" in err_body:
            return False, "TABLE_MISSING", "Table 'public.users' does not exist yet. Run supabase_schema.sql in the Supabase SQL Editor."
        elif e.code == 401:
            return False, "INVALID_KEY", f"Supabase API key is invalid or unauthorized: {err_body}"
        else:
            return False, f"HTTP_{e.code}", f"HTTP {e.code}: {err_body}"
    except Exception as e:
        return False, "NETWORK_ERROR", str(e)

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
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        print(f"[Supabase HTTP Error {e.code}] {method} {url}: {err_msg}")
        return None
    except Exception as e:
        print(f"[Supabase Error] {method} {url}: {str(e)}")
        return None

# -------------------------------------------------------------------
# USER CRUD OPERATIONS
# -------------------------------------------------------------------
def get_user_by_identifier(identifier: str):
    """Find user by username or email (case-insensitive) in Supabase.
    
    PostgREST treats '.' as a delimiter in filter expressions. Values with dots
    (such as email addresses) must be wrapped in double quotes to prevent syntax errors (PGRST100).
    """
    if not is_supabase_configured():
        return None

    ident = identifier.strip().lower()
    quoted_val = urllib.parse.quote(f'"{ident}"')
    raw_val = urllib.parse.quote(ident)

    # If identifier has '@', search email column first
    if "@" in ident:
        for v in [quoted_val, raw_val]:
            results = _supabase_request("users", method="GET", query_params=f"email=ilike.{v}")
            if results and isinstance(results, list) and len(results) > 0:
                return results[0]
        for v in [raw_val, quoted_val]:
            results = _supabase_request("users", method="GET", query_params=f"username=ilike.{v}")
            if results and isinstance(results, list) and len(results) > 0:
                return results[0]
    else:
        for v in [raw_val, quoted_val]:
            results = _supabase_request("users", method="GET", query_params=f"username=ilike.{v}")
            if results and isinstance(results, list) and len(results) > 0:
                return results[0]
        for v in [quoted_val, raw_val]:
            results = _supabase_request("users", method="GET", query_params=f"email=ilike.{v}")
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
    elif isinstance(results, dict) and "id" in results:
        return results
    return None

def create_user(user_dict: dict):
    """Insert a new user into Supabase."""
    if not is_supabase_configured():
        return None

    res = _supabase_request("users", method="POST", payload=user_dict)
    if isinstance(res, list) and len(res) > 0:
        return res[0]
    elif isinstance(res, dict) and "id" in res:
        return res
    return None

def update_user(user_id: str, updates: dict):
    """Update fields for a user in Supabase."""
    if not is_supabase_configured():
        return None

    query = f"id=eq.{urllib.parse.quote(user_id)}"
    res = _supabase_request("users", method="PATCH", payload=updates, query_params=query)
    if isinstance(res, list) and len(res) > 0:
        return res[0]
    elif isinstance(res, dict) and "id" in res:
        return res
    return None
