import json
import urllib.request
import urllib.error
import urllib.parse
import time
import uuid

from backend.supabase_db import get_supabase_config, is_supabase_configured, _supabase_request
from backend.auth import authenticate_user, register_user, find_user_by_identifier

print('=' * 60)
print(' VANGUARD RECON — SUPABASE INTEGRATION TEST SUITE')
print('=' * 60)

# TEST 1: Config Check
url, key = get_supabase_config()
print('\n[TEST 1] Configuration Check:')
print(f' - URL Loaded: {url}')
print(f' - Key Loaded: {"YES (" + key[:12] + "...)" if key else "NO"}')
print(f' - is_supabase_configured(): {is_supabase_configured()}')

if not (url and key):
    print('[FAIL] Supabase credentials missing!')
    exit(1)

# TEST 2: Direct REST Ping
print('\n[TEST 2] Supabase REST API Ping:')
headers = {
    'apikey': key,
    'Authorization': f'Bearer {key}',
    'Content-Type': 'application/json'
}
try:
    req = urllib.request.Request(f'{url}/rest/v1/users?select=count', headers=headers, method='GET')
    with urllib.request.urlopen(req, timeout=8) as response:
        print(f' - HTTP Status Code: {response.status}')
        body = response.read().decode('utf-8')
        print(f' - API Response: {body}')
        print(' - [PASS] Connection to Supabase REST endpoint succeeded.')
except urllib.error.HTTPError as e:
    err_body = e.read().decode('utf-8', errors='ignore')
    print(f' - [HTTP ERROR] {e.code}: {e.reason}')
    print(f' - Response Body: {err_body}')
except Exception as e:
    print(f' - [ERROR]: {str(e)}')

# TEST 3: User Table CRUD Operations
print('\n[TEST 3] CRUD Operations on public.users Table:')
test_id = f'test_{uuid.uuid4().hex[:8]}'
test_username = f'testuser_{int(time.time())}'
test_email = f'{test_username}@example.com'

test_payload = {
    'id': test_id,
    'username': test_username,
    'email': test_email,
    'password_hash': 'test_salt:test_hash',
    'full_name': 'Automated Test User',
    'college': 'Test University',
    'role': 'QA Tester'
}

# 3a. Insert Test User
print(f' - [3a] Inserting test user ({test_username})...')
insert_req = urllib.request.Request(
    f'{url}/rest/v1/users',
    data=json.dumps(test_payload).encode('utf-8'),
    headers={**headers, 'Prefer': 'return=representation'},
    method='POST'
)
try:
    with urllib.request.urlopen(insert_req, timeout=8) as res:
        res_data = json.loads(res.read().decode('utf-8'))
        print(f'   -> Insert result: {res_data}')
        print('   -> [PASS] User record created in Supabase.')
except urllib.error.HTTPError as e:
    err_body = e.read().decode('utf-8', errors='ignore')
    print(f'   -> [FAIL] HTTP {e.code}: {err_body}')
except Exception as e:
    print(f'   -> [FAIL] {str(e)}')

# 3b. Read Test User
print(f' - [3b] Querying test user ({test_username})...')
read_req = urllib.request.Request(
    f'{url}/rest/v1/users?username=eq.{test_username}&select=*',
    headers=headers,
    method='GET'
)
try:
    with urllib.request.urlopen(read_req, timeout=8) as res:
        res_data = json.loads(res.read().decode('utf-8'))
        print(f'   -> Found: {len(res_data)} record(s)')
        if res_data and res_data[0].get('username') == test_username:
            print('   -> [PASS] Read test user verified.')
        else:
            print('   -> [FAIL] Record not matching expected username.')
except Exception as e:
    print(f'   -> [FAIL] {str(e)}')

# 3c. Update Test User
print(f' - [3c] Updating test user ({test_username})...')
patch_req = urllib.request.Request(
    f'{url}/rest/v1/users?id=eq.{test_id}',
    data=json.dumps({'full_name': 'Updated Test Name'}).encode('utf-8'),
    headers={**headers, 'Prefer': 'return=representation'},
    method='PATCH'
)
try:
    with urllib.request.urlopen(patch_req, timeout=8) as res:
        res_data = json.loads(res.read().decode('utf-8'))
        print(f'   -> Updated result: {res_data}')
        print('   -> [PASS] Update operation verified.')
except Exception as e:
    print(f'   -> [FAIL] {str(e)}')

# 3d. Delete Test User (Cleanup)
print(f' - [3d] Cleaning up test user ({test_username})...')
del_req = urllib.request.Request(
    f'{url}/rest/v1/users?id=eq.{test_id}',
    headers={**headers, 'Prefer': 'return=representation'},
    method='DELETE'
)
try:
    with urllib.request.urlopen(del_req, timeout=8) as res:
        res_data = json.loads(res.read().decode('utf-8'))
        print(f'   -> Deleted: {res_data}')
        print('   -> [PASS] Cleanup complete.')
except Exception as e:
    print(f'   -> [FAIL] {str(e)}')

# TEST 4: Application Level Auth Integration
print('\n[TEST 4] App-Level Registration & Authentication:')
reg_user = f'auditor_{uuid.uuid4().hex[:6]}'
reg_res = register_user(reg_user, f'{reg_user}@vanguard.test', 'SecurePassword123!', 'Vanguard Auditor')
print(f' - Register response success: {reg_res.get("success")}')
if reg_res.get('success'):
    print(' - [PASS] New user registered successfully.')
    auth_res = authenticate_user(reg_user, 'SecurePassword123!')
    print(f' - Login response success: {auth_res.get("success")}')
    if auth_res.get('success'):
        print(f' - JWT Token Generated: {auth_res.get("token")[:35]}...')
        print(f' - User details: {auth_res.get("user")}')
        print(' - [PASS] Full end-to-end authentication verified.')
    else:
        print(f' - [FAIL] Login failed: {auth_res.get("error")}')
else:
    print(f' - [FAIL] Registration failed: {reg_res.get("error")}')

print('\n' + '=' * 60)
print(' ALL SUPABASE TESTS COMPLETED')
print('=' * 60)
