/**
 * Vanguard Recon Pro — Authentication & Session Manager
 * Handles JWT token storage, user session validation, auth headers, and UI state.
 */

const VanguardAuth = (() => {
    const TOKEN_KEY = 'vanguard_auth_token';
    const USER_KEY = 'vanguard_auth_user';

    function getAuthToken() {
        return localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY) || null;
    }

    function getCurrentUser() {
        try {
            const raw = localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function isAuthenticated() {
        const token = getAuthToken();
        const user = getCurrentUser();
        return !!(token && user);
    }

    function setAuthSession(token, user, remember = true) {
        const storage = remember ? localStorage : sessionStorage;
        // Clean other storage to prevent desync
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(USER_KEY);

        storage.setItem(TOKEN_KEY, token);
        storage.setItem(USER_KEY, JSON.stringify(user));
    }

    function clearAuthSession() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(USER_KEY);
    }

    async function login(identifier, password, remember = true) {
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier, password })
            });
            const data = await response.json();
            if (response.ok && data.success && data.token) {
                setAuthSession(data.token, data.user, remember);
                return { success: true, user: data.user, token: data.token };
            } else {
                return { success: false, error: data.error || 'Invalid credentials' };
            }
        } catch (err) {
            return { success: false, error: 'Network error communicating with authentication service' };
        }
    }

    async function register(username, email, password, fullName = '', role = '', org = '') {
        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    email,
                    password,
                    full_name: fullName,
                    role,
                    organization: org
                })
            });
            const data = await response.json();
            if (response.ok && data.success && data.token) {
                setAuthSession(data.token, data.user, true);
                return { success: true, user: data.user, token: data.token };
            } else {
                return { success: false, error: data.error || 'Registration failed' };
            }
        } catch (err) {
            return { success: false, error: 'Network error during registration' };
        }
    }

    async function checkAuthStatus() {
        const token = getAuthToken();
        if (!token) return false;

        try {
            const response = await fetch('/api/auth/me', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.user) {
                    const isLocal = !!localStorage.getItem(TOKEN_KEY);
                    setAuthSession(token, data.user, isLocal);
                    return true;
                }
            }
        } catch (e) {}

        // If validation fails
        clearAuthSession();
        return false;
    }

    async function logout() {
        try {
            const token = getAuthToken();
            if (token) {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
            }
        } catch (e) {}
        clearAuthSession();
        window.location.href = 'login.html';
    }

    function requireAuth() {
        // Current file name check
        const path = window.location.pathname;
        const page = path.substring(path.lastIndexOf('/') + 1) || 'index.html';

        if (page === 'login.html' || page === 'login') {
            if (isAuthenticated()) {
                window.location.href = 'index.html';
            }
            return;
        }

        if (!isAuthenticated()) {
            const returnUrl = encodeURIComponent(window.location.href);
            window.location.href = `login.html?returnUrl=${returnUrl}`;
        }
    }

    async function fetchWithAuth(url, options = {}) {
        const headers = options.headers || {};
        const token = getAuthToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        options.headers = headers;

        const res = await fetch(url, options);
        if (res.status === 401) {
            clearAuthSession();
            window.location.href = 'login.html?expired=1';
        }
        return res;
    }

    function setupNavbarUserUI() {
        const user = getCurrentUser();
        const navbar = document.querySelector('.navbar');
        if (!navbar) return;

        // Check if user controls already injected
        if (document.getElementById('navUserControls')) return;

        // Find the rightmost top-level container in navbar
        let rightSection = navbar.querySelector('.nav-right');
        if (!rightSection) {
            const topDivs = Array.from(navbar.children).filter(c => c.tagName === 'DIV');
            rightSection = topDivs.length > 1 ? topDivs[topDivs.length - 1] : navbar;
        }
        if (!rightSection) return;

        if (user) {
            const initials = (user.full_name || user.username || 'AM')
                .split(' ')
                .map(n => n[0])
                .join('')
                .substring(0, 2)
                .toUpperCase();

            const userControls = document.createElement('div');
            userControls.id = 'navUserControls';
            userControls.className = 'nav-user-controls';
            userControls.innerHTML = `
                <a href="profile.html" class="nav-user-badge" title="Logged in as ${user.full_name || user.username}">
                    <span class="user-avatar-mini">${initials}</span>
                    <span class="user-name-mini">${user.full_name || user.username}</span>
                </a>
                <button id="logoutNavBtn" class="hud-btn btn-logout" title="Sign Out">
                    <span>🚪</span>
                    <span style="font-size:11px;">LOGOUT</span>
                </button>
            `;

            rightSection.appendChild(userControls);

            const logoutBtn = document.getElementById('logoutNavBtn');
            if (logoutBtn) {
                logoutBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    if (confirm('Are you sure you want to sign out of Vanguard Recon?')) {
                        logout();
                    }
                });
            }
        } else {
            // Not logged in UI (e.g. if viewing public preview)
            const loginLink = document.createElement('a');
            loginLink.href = 'login.html';
            loginLink.className = 'btn-primary';
            loginLink.style.cssText = 'padding:6px 14px; font-size:12px; text-decoration:none;';
            loginLink.innerText = '🔐 Analyst Login';
            rightSection.appendChild(loginLink);
        }
    }

    return {
        getAuthToken,
        getCurrentUser,
        isAuthenticated,
        setAuthSession,
        clearAuthSession,
        login,
        register,
        logout,
        checkAuthStatus,
        requireAuth,
        fetchWithAuth,
        setupNavbarUserUI
    };
})();

// Auto-run auth check and navbar setup
document.addEventListener('DOMContentLoaded', () => {
    VanguardAuth.requireAuth();
    VanguardAuth.setupNavbarUserUI();
});
