import json
import os
import sys

# Ensure root directory is on sys.path
root_dir = os.path.dirname(os.path.abspath(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.supabase_db import (
    get_supabase_config,
    is_supabase_configured,
    check_supabase_status,
    get_user_by_identifier,
    create_user
)
from backend.auth import load_local_users

def sync():
    print("=" * 65)
    print(" VANGUARD RECON — SUPABASE DATABASE SYNC UTILITY")
    print("=" * 65)

    # Allow passing credentials via command line arguments
    if len(sys.argv) >= 3:
        os.environ['SUPABASE_URL'] = sys.argv[1].strip()
        os.environ['SUPABASE_KEY'] = sys.argv[2].strip()

    url, key = get_supabase_config()
    print(f"\n1. Configuration Check:")
    print(f" - Supabase URL: {url or '[NOT SET]'}")
    print(f" - Supabase Key: {'[CONFIGURED]' if key else '[NOT SET]'}")

    if not is_supabase_configured():
        print("\n[!] Supabase credentials are not found.")
        print("To connect Supabase, add your project credentials to .env or config.json:")
        print("  SUPABASE_URL=https://your-project-id.supabase.co")
        print("  SUPABASE_KEY=your-supabase-anon-or-service-role-key")
        print("\nThen run this script again: python sync_users_to_supabase.py")
        return

    # Check database & table status
    print("\n2. Checking Supabase Database Status...")
    ok, code, msg = check_supabase_status()
    print(f" - Status Code: {code}")
    print(f" - Details:     {msg}")

    if code == "TABLE_MISSING":
        print("\n" + "!" * 65)
        print(" [ACTION REQUIRED] THE 'users' TABLE DOES NOT EXIST IN SUPABASE!")
        print("!" * 65)
        print("\nThe sync script cannot create tables through the REST API.")
        print("To create the table and make it visible in Supabase Table Editor:\n")
        print("  Step 1: Open your Supabase Dashboard (https://supabase.com/dashboard)")
        print("  Step 2: Select your project and click 'SQL Editor' in the left menu.")
        print("  Step 3: Click 'New query' and paste the contents of 'supabase_schema.sql'.")
        print("  Step 4: Click 'Run' (or press Ctrl+Enter).")
        print("\nAfter running the script, go to 'Table Editor' in Supabase.")
        print("The 'users' table will immediately appear with all your accounts pre-seeded!")
        return

    if not ok:
        print(f"\n[!] Connection issue: {msg}")
        return

    print("\n3. Synchronizing Local Accounts to Supabase...")
    users = load_local_users()
    print(f"Found {len(users)} local account(s) to verify.")

    synced_count = 0
    skipped_count = 0
    failed_count = 0

    for uid, user in users.items():
        username = user.get("username")
        email = user.get("email")
        print(f"\n - Checking account: {username} ({email})...")

        existing = get_user_by_identifier(username) or get_user_by_identifier(email)
        if existing:
            print(f"   -> Already in Supabase (id={existing.get('id')}). Skipping.")
            skipped_count += 1
            continue

        res = create_user(user)
        if res:
            print(f"   -> [SUCCESS] Uploaded to Supabase!")
            synced_count += 1
        else:
            print(f"   -> [FAILED] Insert failed.")
            failed_count += 1

    print("\n" + "=" * 65)
    print(f" SYNC RESULT: {synced_count} uploaded, {skipped_count} already existed, {failed_count} failed")
    print("=" * 65)

if __name__ == "__main__":
    sync()
