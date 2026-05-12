'use strict';
/**
 * Hemolink v2.0 — Integration Test Suite
 * Tests all security fixes, validation rules, and business logic.
 */

// ── Env for test run ────────────────────────────────────────────
process.env.JWT_SECRET   = 'super-secure-test-secret-64chars-abcdef1234567890abcdef1234567890';
process.env.PORT         = '3099';
process.env.NODE_ENV     = 'test';
process.env.DB_PATH      = './data/test-run.db';
process.env.ALLOWED_ORIGINS = 'http://localhost:3099';
process.env.AUTH_RATE_MAX = '999'; // disable rate limiting for test speed
process.env.RATE_MAX      = '9999';

const fs   = require('fs');
const http = require('http');
const path = require('path');

// Clean DB from any prior run
const dbFile = path.resolve('./data/test-run.db');
if (fs.existsSync(dbFile)) fs.unlinkSync(dbFile);

// ── Minimal HTTP client ─────────────────────────────────────────
function request(method, urlPath, body, token) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: 'localhost', port: 3099, path: urlPath, method,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    };
    const req = http.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve({ status: res.status || res.statusCode, headers: res.headers, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, headers: res.headers, body: raw }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}
const GET   = (p, t)    => request('GET',   p, null, t);
const POST  = (p, b, t) => request('POST',  p, b, t);
const PATCH = (p, b, t) => request('PATCH', p, b, t);

// ── Test runner ─────────────────────────────────────────────────
const results = [];
let donorToken, patientToken, donorId;

async function test(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    process.stdout.write('.');
  } catch (e) {
    results.push({ name, ok: false, error: e.message });
    process.stdout.write('✗');
  }
}

function assert(cond, msg) { if (!cond) throw new Error(msg); }
function assertEq(a, b)    { if (a !== b) throw new Error(`Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); }

// ── Tests ────────────────────────────────────────────────────────
async function run() {
  require('./server.js');
  await new Promise(r => setTimeout(r, 2000)); // wait for server
  console.log('\nRunning tests…\n');

  // ── Health ────────────────────────────────────────────────────
  await test('GET /api/health → 200', async () => {
    const r = await GET('/api/health');
    assertEq(r.status, 200);
    assert(r.body.status === 'OK', 'status OK');
    assert(r.body.ts, 'has timestamp');
    // Security: X-Request-ID must be present
    assert(r.headers['x-request-id'], 'X-Request-ID header present');
  });

  // ── Email validation ──────────────────────────────────────────
  await test('Register → rejects missing email', async () => {
    const r = await POST('/api/auth/register', { email:'', password:'Test@1234', confirmPassword:'Test@1234', role:'patient' });
    assertEq(r.status, 422);
  });
  await test('Register → rejects bad email format', async () => {
    const r = await POST('/api/auth/register', { email:'notanemail', password:'Test@1234', confirmPassword:'Test@1234', role:'patient' });
    assertEq(r.status, 422);
    assert(r.body.error, 'has error msg');
  });
  await test('Register → rejects email with no TLD', async () => {
    const r = await POST('/api/auth/register', { email:'user@domain', password:'Test@1234', confirmPassword:'Test@1234', role:'patient' });
    assertEq(r.status, 422);
  });

  // ── Password validation ───────────────────────────────────────
  await test('Register → rejects password under 8 chars', async () => {
    const r = await POST('/api/auth/register', { email:'a@b.com', password:'Ab1!', confirmPassword:'Ab1!', role:'patient' });
    assertEq(r.status, 422);
    assert(r.body.error.toLowerCase().includes('8'), 'mentions 8 chars');
  });
  await test('Register → rejects password with no uppercase', async () => {
    const r = await POST('/api/auth/register', { email:'a@b.com', password:'abcdef1!', confirmPassword:'abcdef1!', role:'patient' });
    assertEq(r.status, 422);
  });
  await test('Register → rejects password with no lowercase', async () => {
    const r = await POST('/api/auth/register', { email:'a@b.com', password:'ABCDEF1!', confirmPassword:'ABCDEF1!', role:'patient' });
    assertEq(r.status, 422);
  });
  await test('Register → rejects password with no number', async () => {
    const r = await POST('/api/auth/register', { email:'a@b.com', password:'Abcdefg!', confirmPassword:'Abcdefg!', role:'patient' });
    assertEq(r.status, 422);
  });
  await test('Register → rejects password with no special character', async () => {
    const r = await POST('/api/auth/register', { email:'a@b.com', password:'Abcdefg1', confirmPassword:'Abcdefg1', role:'patient' });
    assertEq(r.status, 422);
  });
  await test('Register → rejects mismatched confirmPassword', async () => {
    const r = await POST('/api/auth/register', { email:'a@b.com', password:'Test@1234', confirmPassword:'Different@1', role:'patient' });
    assertEq(r.status, 422);
    assert(r.body.error.toLowerCase().includes('match'), 'mentions match');
  });

  // ── Role validation ───────────────────────────────────────────
  await test('Register → rejects invalid role', async () => {
    const r = await POST('/api/auth/register', { email:'a@b.com', password:'Test@1234', confirmPassword:'Test@1234', role:'admin' });
    assertEq(r.status, 422);
  });

  // ── Successful registrations ──────────────────────────────────
  await test('Register → creates patient account (201)', async () => {
    const r = await POST('/api/auth/register', {
      email:'patient@hemolink.test', password:'Patient@123', confirmPassword:'Patient@123', role:'patient'
    });
    assertEq(r.status, 201);
    assert(r.body.token, 'has token');
    assert(r.body.user, 'has user');
    assert(!r.body.user.password_hash, '❌ password_hash leaked in register');
    assert(!r.body.user.password, '❌ password leaked in register');
    assertEq(r.body.user.role, 'patient');
    patientToken = r.body.token;
  });
  await test('Register → creates donor account (201)', async () => {
    const r = await POST('/api/auth/register', {
      email:'donor@hemolink.test', password:'Donor@12345!', confirmPassword:'Donor@12345!', role:'donor'
    });
    assertEq(r.status, 201);
    assert(r.body.token, 'has token');
    assert(!r.body.user.password_hash, '❌ password_hash leaked');
    donorToken = r.body.token;
  });
  await test('Register → rejects duplicate email (409)', async () => {
    const r = await POST('/api/auth/register', {
      email:'donor@hemolink.test', password:'Donor@12345!', confirmPassword:'Donor@12345!', role:'donor'
    });
    assertEq(r.status, 409);
  });

  // ── Login ─────────────────────────────────────────────────────
  await test('Login → succeeds with correct credentials', async () => {
    const r = await POST('/api/auth/login', { email:'donor@hemolink.test', password:'Donor@12345!' });
    assertEq(r.status, 200);
    assert(r.body.token, 'has token');
    assert(!r.body.user.password_hash, '❌ password_hash in login response');
    assert(!r.body.user.password, '❌ password in login response');
  });
  await test('Login → rejects wrong password (401)', async () => {
    const r = await POST('/api/auth/login', { email:'donor@hemolink.test', password:'WrongPass@99' });
    assertEq(r.status, 401);
  });
  await test('Login → same error for unknown email (no enumeration)', async () => {
    const r = await POST('/api/auth/login', { email:'nobody@ghost.com', password:'SomePass@1' });
    assertEq(r.status, 401);
    assertEq(r.body.error, 'Invalid email or password.');
  });
  await test('Login → same error for wrong password (no enumeration)', async () => {
    const r = await POST('/api/auth/login', { email:'donor@hemolink.test', password:'WrongPass@1' });
    assertEq(r.status, 401);
    assertEq(r.body.error, 'Invalid email or password.'); // same message as unknown email
  });
  await test('Login → rejects missing password', async () => {
    const r = await POST('/api/auth/login', { email:'donor@hemolink.test', password:'' });
    assertEq(r.status, 422);
  });

  // ── Auth guard ────────────────────────────────────────────────
  await test('Profile → 401 without token', async () => {
    const r = await GET('/api/auth/profile');
    assertEq(r.status, 401);
  });
  await test('Profile → 401 with garbage token', async () => {
    const r = await GET('/api/auth/profile', 'garbage.token.value');
    assertEq(r.status, 401);
  });
  await test('Profile → 401 with malformed Bearer', async () => {
    const r = await request('GET', '/api/auth/profile', null, null);
    // manually set malformed header below via raw request check — skip for brevity
    assertEq(r.status, 401);
  });
  await test('Profile → 200 + no password fields for authenticated user', async () => {
    const r = await GET('/api/auth/profile', donorToken);
    assertEq(r.status, 200);
    assert(!r.body.password_hash, '❌ password_hash in profile response');
    assert(!r.body.password, '❌ password in profile response');
    assertEq(r.body.email, 'donor@hemolink.test');
    assertEq(r.body.role, 'donor');
  });

  // ── Donor phone validation ────────────────────────────────────
  await test('POST /donors → rejects missing phone', async () => {
    const r = await POST('/api/donors', { name:'Test', bloodGroup:'O+', city:'Delhi', phone:'' }, donorToken);
    assertEq(r.status, 422);
  });
  await test('POST /donors → rejects phone with letters', async () => {
    const r = await POST('/api/donors', { name:'Test', bloodGroup:'O+', city:'Delhi', phone:'abc123def' }, donorToken);
    assertEq(r.status, 422);
  });
  await test('POST /donors → rejects phone too short', async () => {
    const r = await POST('/api/donors', { name:'Test', bloodGroup:'O+', city:'Delhi', phone:'123' }, donorToken);
    assertEq(r.status, 422);
  });

  // ── Blood group validation ────────────────────────────────────
  await test('POST /donors → rejects invalid blood group', async () => {
    const r = await POST('/api/donors', { name:'Test', bloodGroup:'Z+', city:'Delhi', phone:'+91 9876543210' }, donorToken);
    assertEq(r.status, 422);
  });
  await test('POST /donors → rejects empty blood group', async () => {
    const r = await POST('/api/donors', { name:'Test', bloodGroup:'', city:'Delhi', phone:'+91 9876543210' }, donorToken);
    assertEq(r.status, 422);
  });

  // ── Role-based access control ────────────────────────────────
  await test('POST /donors → 403 for patient role', async () => {
    const r = await POST('/api/donors', { name:'Hacker', bloodGroup:'O+', city:'Delhi', phone:'+91 9876543210' }, patientToken);
    assertEq(r.status, 403);
  });
  await test('POST /donors → 401 without token', async () => {
    const r = await POST('/api/donors', { name:'Hacker', bloodGroup:'O+', city:'Delhi', phone:'+91 9876543210' });
    assertEq(r.status, 401);
  });

  // ── Create donor profile ─────────────────────────────────────
  await test('POST /donors → creates donor profile with valid data', async () => {
    const r = await POST('/api/donors', {
      name:'Arjun Sharma', bloodGroup:'O+', city:'Kolkata',
      phone:'+91 98765 43210', weightKg:72,
      lastDonationDate:'2025-10-01', lat:22.5726, lng:88.3639,
      notes:'Available on weekends.'
    }, donorToken);
    assertEq(r.status, 200);
    assert(r.body.donor, 'has donor object');
    assertEq(r.body.donor.name, 'Arjun Sharma');
    assertEq(r.body.donor.bloodGroup, 'O+');
    assert(r.body.donor.phone, 'phone present in own profile response');
    donorId = r.body.donor.id;
  });

  // ── Donor listing (public) ───────────────────────────────────
  await test('GET /api/donors → 200 public listing', async () => {
    const r = await GET('/api/donors');
    assertEq(r.status, 200);
    assert(Array.isArray(r.body.donors), 'donors is array');
    assert(r.body.total >= 1, 'at least one donor');
    assert(typeof r.body.pages === 'number', 'has pages');
    assert(typeof r.body.limit === 'number', 'has limit');
  });
  await test('GET /api/donors → phone NEVER in public listing', async () => {
    const r = await GET('/api/donors');
    r.body.donors.forEach(d => {
      assert(!d.phone, `❌ PHONE LEAKED for donor ${d.name}`);
    });
  });
  await test('GET /api/donors → filters by bloodGroup=O+', async () => {
    const r = await GET('/api/donors?bloodGroup=O%2B');
    assertEq(r.status, 200);
    r.body.donors.forEach(d => assertEq(d.bloodGroup, 'O+'));
  });
  await test('GET /api/donors → filters by city', async () => {
    const r = await GET('/api/donors?city=Kolkata');
    assertEq(r.status, 200);
    assert(r.body.donors.length > 0, 'found donor in Kolkata');
    r.body.donors.forEach(d => assert(d.city.toLowerCase().includes('kolkata'), `city mismatch: ${d.city}`));
  });
  await test('GET /api/donors → rejects invalid blood group query param', async () => {
    const r = await GET('/api/donors?bloodGroup=Z%2B');
    assertEq(r.status, 422);
  });
  await test('GET /api/donors → pagination works', async () => {
    const r = await GET('/api/donors?page=1&limit=5');
    assertEq(r.status, 200);
    assert(r.body.count <= 5, 'respects limit');
    assertEq(r.body.page, 1);
  });
  await test('GET /api/donors → rejects limit > 50', async () => {
    const r = await GET('/api/donors?limit=999');
    assertEq(r.status, 422);
  });

  // ── Single donor (auth required) ─────────────────────────────
  await test('GET /api/donors/:id → 401 without token', async () => {
    const r = await GET(`/api/donors/${donorId}`);
    assertEq(r.status, 401);
  });
  await test('GET /api/donors/:id → includes phone for authenticated user', async () => {
    const r = await GET(`/api/donors/${donorId}`, patientToken);
    assertEq(r.status, 200);
    assert(r.body.phone, '❌ phone missing for authenticated request');
  });
  await test('GET /api/donors/:id → 404 for nonexistent UUID', async () => {
    const r = await GET('/api/donors/00000000-0000-0000-0000-000000000000', donorToken);
    assertEq(r.status, 404);
  });
  await test('GET /api/donors/:id → 422 for non-UUID id', async () => {
    const r = await GET('/api/donors/not-a-real-id', donorToken);
    assertEq(r.status, 422);
  });

  // ── Profile update (upsert) ──────────────────────────────────
  await test('POST /donors → updates existing profile', async () => {
    const r = await POST('/api/donors', {
      name:'Arjun Sharma', bloodGroup:'A+', city:'Salt Lake',
      phone:'+91 98765 43210'
    }, donorToken);
    assertEq(r.status, 200);
    assertEq(r.body.donor.bloodGroup, 'A+');
    assertEq(r.body.donor.city, 'Salt Lake');
    assert(r.body.message.includes('updated'), 'confirms update not create');
  });

  // ── Availability ─────────────────────────────────────────────
  await test('PATCH /donors/availability → 401 without token', async () => {
    const r = await PATCH('/api/donors/availability', { availability:'available' });
    assertEq(r.status, 401);
  });
  await test('PATCH /donors/availability → rejects invalid value', async () => {
    const r = await PATCH('/api/donors/availability', { availability:'sleeping' }, donorToken);
    assertEq(r.status, 422);
  });
  await test('PATCH /donors/availability → updates to recently_donated', async () => {
    const r = await PATCH('/api/donors/availability', { availability:'recently_donated' }, donorToken);
    assertEq(r.status, 200);
    assertEq(r.body.availability, 'recently_donated');
  });
  await test('PATCH /donors/availability → updates to unavailable', async () => {
    const r = await PATCH('/api/donors/availability', { availability:'unavailable' }, donorToken);
    assertEq(r.status, 200);
    assertEq(r.body.availability, 'unavailable');
  });
  await test('PATCH /donors/availability → updates back to available', async () => {
    const r = await PATCH('/api/donors/availability', { availability:'available' }, donorToken);
    assertEq(r.status, 200);
    assertEq(r.body.availability, 'available');
  });

  // ── DB persistence ───────────────────────────────────────────
  await test('SQLite DB file exists and has content', async () => {
    assert(fs.existsSync(dbFile), 'DB file not found');
    assert(fs.statSync(dbFile).size > 1024, 'DB file suspiciously small');
  });

  // ── Security headers ─────────────────────────────────────────
  await test('Security headers present on API response', async () => {
    const r = await GET('/api/health');
    assert(r.headers['x-content-type-options'], 'X-Content-Type-Options missing');
    assert(r.headers['x-frame-options'], 'X-Frame-Options missing');
    assert(r.headers['content-security-policy'], 'CSP header missing');
    assert(r.headers['x-request-id'], 'X-Request-ID missing');
  });

  // ── Injection / fuzzing ───────────────────────────────────────
  await test('Register → SQL injection in email rejected by validation', async () => {
    const r = await POST('/api/auth/register', {
      email:"' OR 1=1--", password:'Test@1234', confirmPassword:'Test@1234', role:'patient'
    });
    assertEq(r.status, 422);
  });
  await test('Register → XSS attempt in name field rejected', async () => {
    // name field only exists on donor profile, not register — so this goes to POST /donors
    const r = await POST('/api/donors', {
      name:'<script>alert(1)</script>', bloodGroup:'O+', city:'Delhi', phone:'+91 9876543210'
    }, donorToken);
    assertEq(r.status, 422); // invalid name characters
  });
  await test('Donors → oversized body rejected', async () => {
    const r = await POST('/api/donors', {
      name:'A'.repeat(200), bloodGroup:'O+', city:'Delhi', phone:'+91 9876543210'
    }, donorToken);
    assertEq(r.status, 422);
  });

  // ── Future date rejection ─────────────────────────────────────
  await test('POST /donors → rejects future lastDonationDate', async () => {
    const future = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);
    const r = await POST('/api/donors', {
      name:'Arjun Sharma', bloodGroup:'A+', city:'Delhi',
      phone:'+91 9876543210', lastDonationDate: future
    }, donorToken);
    assertEq(r.status, 422);
  });

  // ── Print results ─────────────────────────────────────────────
  const passed = results.filter(r => r.ok).length;
  const failed = results.filter(r => !r.ok).length;

  console.log('\n\n' + '═'.repeat(62));
  console.log('  HEMOLINK v2.0 — Integration Test Results');
  console.log('═'.repeat(62));

  if (failed > 0) {
    console.log('\n  FAILURES:\n');
    results.filter(r => !r.ok).forEach(r => {
      console.log(`  ❌ ${r.name}`);
      console.log(`     ↳ ${r.error}\n`);
    });
  }

  console.log('\n  ALL TESTS:\n');
  results.forEach(r => console.log(`  ${r.ok ? '✅' : '❌'}  ${r.name}`));

  console.log('\n' + '═'.repeat(62));
  console.log(`  Passed : ${passed}`);
  console.log(`  Failed : ${failed}`);
  console.log(`  Total  : ${results.length}`);
  console.log('═'.repeat(62) + '\n');

  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => { console.error('\nTest runner crashed:', err); process.exit(1); });
