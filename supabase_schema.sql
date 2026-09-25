-- ========================================================
-- Vanguard Recon — Supabase Database Schema
-- ========================================================
-- Run this script in your Supabase SQL Editor:
-- (Dashboard -> SQL Editor -> New query -> Paste & Run)

-- 1. Create the Users Table
CREATE TABLE IF NOT EXISTS public.users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    college TEXT DEFAULT 'College / University',
    role TEXT DEFAULT 'Student Developer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Create Indexes for fast lookup by username and email
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users (email);

-- 3. Enable Row Level Security (RLS) & allow standard operations
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Allow anon and authenticated clients to read/insert/update user records
DROP POLICY IF EXISTS "Allow public read access" ON public.users;
CREATE POLICY "Allow public read access" ON public.users FOR SELECT USING (true);

DROP POLICY IF EXISTS "Allow public insert access" ON public.users;
CREATE POLICY "Allow public insert access" ON public.users FOR INSERT WITH CHECK (true);

DROP POLICY IF EXISTS "Allow public update access" ON public.users;
CREATE POLICY "Allow public update access" ON public.users FOR UPDATE USING (true);

-- 4. Seed Default & Registered Accounts
INSERT INTO public.users (id, username, email, password_hash, full_name, college, role, created_at)
VALUES 
(
    'usr_student_01',
    'student',
    'student@college.edu',
    '649ba38feee5408b08ebbaeb615e47fb:3111fdbbcfa9bdfb1fe6a1276ae68e8e7a687353f86e3f7c4613b5bfdb8d94e1',
    'Student Developer',
    'Engineering & Technology Institute',
    'Student Web Developer',
    NOW()
),
(
    'usr_admin_01',
    'admin',
    'admin@vanguard.io',
    '649ba38feee5408b08ebbaeb615e47fb:62e3df29c2ea553335532ba7c6c4c92576b5c3ff2bb475ec1f08e4aa730598fa',
    'Lead Security Analyst',
    'Vanguard Defense Labs',
    'Lead Security Analyst (Admin)',
    NOW()
),
(
    'usr_d1d458cbcf',
    'pjc',
    'chavanpranav2024@gmaill.com',
    'dd632b94e27a0c078ce57312b1602aa9:4c967a61331cecdb43d425df5f8b591674e90d69e127caa05fccc46827690891',
    'Pranav Chavan',
    'MMCOE College',
    'Student Developer',
    NOW()
),
(
    'usr_e72b228a72',
    'jay2811',
    'pranavchavan2024.it@mmcoe.edu.in',
    '7980a9bfaca68d37f6b83f1e1d38e894:db11cb439dd591c1852d13cda86cbb6a2941eb4a239d3ab2382c4ec380e568cb',
    'jay',
    'mmcoe',
    'student',
    NOW()
)
ON CONFLICT (id) DO NOTHING;
