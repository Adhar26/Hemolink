/* ─── Hemolink — Shared Frontend Utilities ───────────────────── */
'use strict';

/* ── Auth session ─────────────────────────────────────────────── */
const Auth = {
  getToken:   () => localStorage.getItem('hl_token'),
  getUser:    () => { try { return JSON.parse(localStorage.getItem('hl_user')); } catch { return null; } },
  setSession: (token, user) => {
    localStorage.setItem('hl_token', token);
    localStorage.setItem('hl_user', JSON.stringify(user));
  },
  clear: () => {
    localStorage.removeItem('hl_token');
    localStorage.removeItem('hl_user');
  },
  isLoggedIn: () => !!localStorage.getItem('hl_token'),
};

/* ── API client ───────────────────────────────────────────────── */
const API = {
  base: '/api',

  async request(method, path, body = null, needsAuth = false) {
    const headers = { 'Content-Type': 'application/json' };

    if (needsAuth) {
      const token = Auth.getToken();
      if (!token) { Auth.clear(); window.location.href = '/login.html'; return null; }
      headers['Authorization'] = `Bearer ${token}`;
    }

    let res, data;
    try {
      res  = await fetch(this.base + path, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });
      data = await res.json().catch(() => ({}));
    } catch {
      return { ok: false, status: 0, data: { error: 'Network error — could not reach server.' } };
    }

    // Token expired or revoked
    if (res.status === 401 && needsAuth) {
      Auth.clear();
      showToast('Session expired. Please sign in again.', 'error');
      setTimeout(() => window.location.href = '/login.html', 1200);
      return null;
    }

    return { ok: res.ok, status: res.status, data };
  },

  get:   (path, auth = false)        => API.request('GET',   path, null, auth),
  post:  (path, body, auth = false)  => API.request('POST',  path, body, auth),
  patch: (path, body, auth = false)  => API.request('PATCH', path, body, auth),
};

/* ── Toast notifications ──────────────────────────────────────── */
function showToast(message, type = 'info', duration = 3500) {
  let c = document.getElementById('toast-container');
  if (!c) {
    c = document.createElement('div');
    c.id = 'toast-container';
    c.style.cssText = 'position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;';
    document.body.appendChild(c);
  }
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = message;
  t.style.cssText = 'padding:.65rem 1rem;border-radius:8px;font-size:.875rem;max-width:320px;word-break:break-word;box-shadow:0 4px 12px rgba(0,0,0,.12);opacity:1;transition:opacity .3s;cursor:pointer;';
  const bg = { success:'#15803d', error:'#dc2626', info:'#1d4ed8', warning:'#d97706' };
  t.style.background = bg[type] || bg.info;
  t.style.color = '#fff';
  t.onclick = () => t.remove();
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 320); }, duration);
}

/* ── Inline alerts ────────────────────────────────────────────── */
function showAlert(containerId, msg, type = 'error') {
  const el = document.getElementById(containerId);
  if (!el) return;
  const colors = {
    error:   { bg:'#fef2f2', border:'#fca5a5', text:'#991b1b' },
    success: { bg:'#f0fdf4', border:'#86efac', text:'#166534' },
    info:    { bg:'#eff6ff', border:'#93c5fd', text:'#1e3a8a' },
  };
  const c = colors[type] || colors.error;
  el.innerHTML = `<div style="background:${c.bg};border:1px solid ${c.border};color:${c.text};padding:.65rem .9rem;border-radius:8px;font-size:.875rem;margin-bottom:.75rem;">${escHtml(msg)}</div>`;
}
function clearAlert(id) { const el = document.getElementById(id); if (el) el.innerHTML = ''; }

/* ── Shared helpers ───────────────────────────────────────────── */
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#039;');
}

function setBtnLoading(btn, loading) {
  if (!btn) return;
  if (loading) {
    btn.dataset.orig = btn.innerHTML;
    btn.innerHTML    = '<span class="spinner"></span> Please wait…';
    btn.disabled     = true;
  } else {
    btn.innerHTML = btn.dataset.orig || btn.textContent;
    btn.disabled  = false;
  }
}

function formatDate(d) {
  if (!d) return '—';
  try { return new Date(d).toLocaleDateString('en-IN', { day:'numeric', month:'short', year:'numeric' }); }
  catch { return d; }
}

function availBadge(status) {
  const map = {
    available:        { label:'Available',       color:'#16a34a' },
    recently_donated: { label:'Recent Donor',    color:'#d97706' },
    unavailable:      { label:'Unavailable',     color:'#dc2626' },
  };
  const s = map[status] || { label: status, color:'#6b7280' };
  return `<span style="display:inline-block;padding:2px 10px;border-radius:99px;font-size:.75rem;font-weight:600;background:${s.color}20;color:${s.color}">${escHtml(s.label)}</span>`;
}

function requireAuth() {
  if (!Auth.isLoggedIn()) { window.location.href = '/login.html'; return false; }
  return true;
}
function redirectIfLoggedIn(dest = '/dashboard.html') {
  if (Auth.isLoggedIn()) window.location.href = dest;
}

/* ── Navigation ───────────────────────────────────────────────── */
function renderNav() {
  const navLinks = document.getElementById('nav-links');
  if (!navLinks) return;
  if (Auth.isLoggedIn()) {
    navLinks.innerHTML = `
      <a href="/search.html">Find Donors</a>
      <a href="/dashboard.html">Dashboard</a>
      <button class="btn btn-outline btn-sm" onclick="logout()">Sign Out</button>`;
  } else {
    navLinks.innerHTML = `
      <a href="/search.html">Find Donors</a>
      <a href="/login.html">Sign In</a>
      <a href="/register.html" class="btn btn-primary btn-sm">Register</a>`;
  }
}
function logout() {
  Auth.clear();
  showToast('Signed out successfully.', 'info');
  setTimeout(() => window.location.href = '/', 800);
}

/* ── Geolocation ──────────────────────────────────────────────── */
function getGeolocation() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error('Geolocation is not supported by your browser.'));
      return;
    }
    navigator.geolocation.getCurrentPosition(
      pos => resolve({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
      ()  => reject(new Error('Location access denied. Enter coordinates manually.'))
    );
  });
}
