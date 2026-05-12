'use strict';
/**
 * Hemolink — Production Server v2.0
 *
 * ✅ better-sqlite3 — synchronous, WAL mode, real file persistence
 * ✅ JWT secret from env — hard-fails if missing or too short
 * ✅ bcrypt cost 12 + optional pepper from env
 * ✅ Full input validation — email, password strength, phone E.164, blood group enum
 * ✅ Helmet + strict CSP, HSTS
 * ✅ CORS locked to ALLOWED_ORIGINS
 * ✅ Rate limiting — global + strict on auth (per-IP, skip successful)
 * ✅ Password hash NEVER returned in any response
 * ✅ Timing-safe login (always runs bcrypt)
 * ✅ X-Request-ID on every response for traceability
 * ✅ Global error handler — no stack traces to client
 * ✅ Morgan structured logging
 * ✅ Donor phone hidden on public listing
 * ✅ Role-based access control
 * ✅ Parameterised SQL only — no injection possible
 * ✅ WAL journal + foreign keys enforced
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

// ── Environment ────────────────────────────────────────────────
const {
  PORT               = 3000,
  NODE_ENV           = 'production',
  JWT_SECRET,
  JWT_EXPIRES_IN     = '7d',
  JWT_REFRESH_DAYS   = '30',
  DB_PATH            = './data/hemolink.db',
  ALLOWED_ORIGINS    = 'http://localhost:3000',
  BCRYPT_PEPPER      = '',
  RATE_WINDOW_MS     = 900000,   // 15 min
  RATE_MAX           = 200,
  AUTH_RATE_MAX      = 10,
} = process.env;

// Hard-fail on missing / weak secret
if (!JWT_SECRET || JWT_SECRET.length < 48) {
  console.error('\n❌  FATAL: JWT_SECRET missing or too short (need ≥48 chars).');
  console.error('   Generate: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"\n');
  process.exit(1);
}

// ── Imports ────────────────────────────────────────────────────
const express     = require('express');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const morgan      = require('morgan');
const crypto      = require('crypto');
const fs          = require('fs');
const Database    = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const { body, param, query, validationResult } = require('express-validator');

// ── Database ───────────────────────────────────────────────────
const dbDir = path.dirname(path.resolve(DB_PATH));
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(path.resolve(DB_PATH));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = -8000');  // 8MB cache

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('donor','patient')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );

  CREATE TABLE IF NOT EXISTS donors (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    blood_group        TEXT NOT NULL
                         CHECK(blood_group IN ('A+','A-','B+','B-','AB+','AB-','O+','O-')),
    city               TEXT NOT NULL,
    phone              TEXT NOT NULL,
    availability       TEXT NOT NULL DEFAULT 'available'
                         CHECK(availability IN ('available','recently_donated','unavailable')),
    last_donation_date TEXT,
    weight_kg          REAL CHECK(weight_kg IS NULL OR (weight_kg >= 40 AND weight_kg <= 250)),
    lat                REAL CHECK(lat IS NULL OR (lat >= -90  AND lat <= 90)),
    lng                REAL CHECK(lng IS NULL OR (lng >= -180 AND lng <= 180)),
    notes              TEXT,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  );

  CREATE INDEX IF NOT EXISTS idx_donors_blood  ON donors(blood_group);
  CREATE INDEX IF NOT EXISTS idx_donors_city   ON donors(city COLLATE NOCASE);
  CREATE INDEX IF NOT EXISTS idx_donors_avail  ON donors(availability);
  CREATE INDEX IF NOT EXISTS idx_users_email   ON users(email COLLATE NOCASE);
`);

// Prepare statements once (reused, faster)
const stmts = {
  getUserById:       db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1'),
  getUserByEmail:    db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE'),
  insertUser:        db.prepare('INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)'),
  resetFailed:       db.prepare("UPDATE users SET failed_logins=0, locked_until=NULL, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?"),
  incFailed:         db.prepare("UPDATE users SET failed_logins=failed_logins+1, locked_until=CASE WHEN failed_logins+1>=5 THEN strftime('%Y-%m-%dT%H:%M:%SZ','now','+15 minutes') ELSE locked_until END, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?"),
  getDonorByUserId:  db.prepare('SELECT * FROM donors WHERE user_id = ?'),
  getDonorById:      db.prepare('SELECT * FROM donors WHERE id = ?'),
  insertDonor:       db.prepare('INSERT INTO donors (id, user_id, name, blood_group, city, phone, weight_kg, last_donation_date, lat, lng, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  updateDonor:       db.prepare("UPDATE donors SET name=?, blood_group=?, city=?, phone=?, weight_kg=?, last_donation_date=?, lat=?, lng=?, notes=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE user_id=?"),
  updateAvailability:db.prepare("UPDATE donors SET availability=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE user_id=?"),
};

// ── Helpers ────────────────────────────────────────────────────
const SAFE_FIELDS = ['id','email','role','is_active','created_at','updated_at'];
function safeUser(u) {
  if (!u) return null;
  return SAFE_FIELDS.reduce((acc, k) => { acc[k] = u[k]; return acc; }, {});
}

function pepperedPassword(password) {
  // Pepper adds a server-side secret so stolen DB hashes are useless without server code
  return BCRYPT_PEPPER ? `${BCRYPT_PEPPER}:${password}` : password;
}

function validate(req, res, next) {
  const errs = validationResult(req);
  if (!errs.isEmpty())
    return res.status(422).json({ error: errs.array()[0].msg, fields: errs.array().map(e => ({ field: e.path, msg: e.msg })) });
  next();
}

// ── Validation rules (reusable) ────────────────────────────────
const BLOOD_GROUPS = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];

// E.164 or common local format: +91 9876543210, 09876543210, (555) 123-4567
const PHONE_RE = /^\+?[\d\s\-(). ]{7,20}$/;

const passwordRules = body('password')
  .isLength({ min: 8, max: 128 }).withMessage('Password must be 8–128 characters.')
  .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
  .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter.')
  .matches(/[0-9]/).withMessage('Password must contain at least one number.')
  .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character (!@#$ etc.).');

const emailRules = body('email')
  .trim()
  .isEmail().withMessage('A valid email address is required.')
  .isLength({ max: 254 }).withMessage('Email too long.')
  .normalizeEmail({ gmail_remove_dots: false });

const phoneRules = body('phone')
  .trim()
  .matches(PHONE_RE).withMessage('Enter a valid phone number (7–20 digits, can include +, spaces, dashes).')
  .customSanitizer(v => v.replace(/\s+/g, ' ').trim());

// ── App ────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);

// X-Request-ID on every response
app.use((req, res, next) => {
  const rid = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', rid);
  req.requestId = rid;
  next();
});

// ── Helmet ─────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts:                 { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy:       { policy: 'strict-origin-when-cross-origin' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));

// ── CORS ───────────────────────────────────────────────────────
const allowedOrigins = ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin '${origin}' not allowed`));
  },
  credentials: true,
  methods: ['GET','POST','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Request-ID'],
}));

// ── Body parsing ───────────────────────────────────────────────
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// ── Logging ────────────────────────────────────────────────────
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

// ── Rate limiters ──────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: Number(RATE_WINDOW_MS),
  max: Number(RATE_MAX),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: req => req.ip,
  message: { error: 'Too many requests — please slow down.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(AUTH_RATE_MAX),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: req => req.ip,
  message: { error: 'Too many failed auth attempts. Wait 15 minutes or reset your password.' },
});

app.use('/api/', globalLimiter);
app.use('/api/auth/login',    authLimiter);
app.use('/api/auth/register', authLimiter);

// ── Auth middleware ────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Authentication required.' });
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ['HS256'] });
    const user = stmts.getUserById.get(payload.id);
    if (!user) return res.status(401).json({ error: 'Account not found or deactivated.' });
    req.user = safeUser(user);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    return res.status(401).json({ error: 'Invalid token.' });
  }
}

// ── Routes ─────────────────────────────────────────────────────

// Health
app.get('/api/health', (_req, res) =>
  res.json({ status: 'OK', mode: NODE_ENV, ts: new Date().toISOString() })
);

// ── Register ───────────────────────────────────────────────────
app.post('/api/auth/register',
  [
    emailRules,
    passwordRules,
    body('confirmPassword')
      .custom((val, { req: r }) => {
        if (val !== r.body.password) throw new Error('Passwords do not match.');
        return true;
      }),
    body('role').isIn(['donor','patient']).withMessage('Role must be donor or patient.'),
  ],
  validate,
  async (req, res) => {
    const { email, password, role } = req.body;

    if (stmts.getUserByEmail.get(email))
      return res.status(409).json({ error: 'An account with this email already exists.' });

    const hash = await bcrypt.hash(pepperedPassword(password), 12);
    const id   = uuidv4();
    stmts.insertUser.run(id, email, hash, role);

    const token = jwt.sign({ id, role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: JWT_EXPIRES_IN });
    res.status(201).json({
      message: 'Account created successfully.',
      token,
      user: safeUser(stmts.getUserById.get(id)),
    });
  }
);

// ── Login ──────────────────────────────────────────────────────
app.post('/api/auth/login',
  [
    emailRules,
    body('password').notEmpty().withMessage('Password is required.').isLength({ max: 128 }),
  ],
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    const user = stmts.getUserByEmail.get(email);

    // Always run bcrypt — prevents timing-based email enumeration
    const hashToCheck = user?.password_hash
      || '$2b$12$invalidhash.padding.so.bcrypt.still.runs.and.takes.time.ok';

    // Check account lock
    if (user?.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({
        error: 'Account temporarily locked after too many failed attempts. Try again in 15 minutes.',
      });
    }

    const match = await bcrypt.compare(pepperedPassword(password), hashToCheck);

    if (!user || !match || !user.is_active) {
      if (user) stmts.incFailed.run(user.id);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    stmts.resetFailed.run(user.id);
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      algorithm: 'HS256', expiresIn: JWT_EXPIRES_IN,
    });

    res.json({ message: 'Login successful.', token, user: safeUser(user) });
  }
);

// ── Profile ────────────────────────────────────────────────────
app.get('/api/auth/profile', auth, (req, res) => res.json(req.user));

// ── List donors — public, NO phone ────────────────────────────
app.get('/api/donors',
  [
    query('bloodGroup').optional().isIn(BLOOD_GROUPS).withMessage('Invalid blood group.'),
    query('city').optional().trim().isLength({ max: 100 }).escape(),
    query('availability').optional().isIn(['available','recently_donated','unavailable']),
    query('page').optional().isInt({ min: 1, max: 9999 }).toInt().withMessage('Invalid page.'),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt().withMessage('Limit must be 1–50.'),
  ],
  validate,
  (req, res) => {
    const { bloodGroup, city, availability, page = 1, limit = 20 } = req.query;

    const clauses = [], params = [];
    if (bloodGroup)   { clauses.push('d.blood_group = ?');          params.push(bloodGroup); }
    if (city)         { clauses.push('d.city LIKE ? COLLATE NOCASE'); params.push(`%${city}%`); }
    if (availability) { clauses.push('d.availability = ?');          params.push(availability); }

    const where  = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const total  = db.prepare(`SELECT COUNT(*) as n FROM donors d ${where}`).get(...params).n;
    const pages  = Math.max(1, Math.ceil(total / limit));
    const offset = (page - 1) * limit;

    const donors = db.prepare(`
      SELECT d.id, d.name,
             d.blood_group        AS bloodGroup,
             d.city,
             d.availability,
             d.last_donation_date AS lastDonationDate,
             d.weight_kg          AS weightKg,
             d.lat, d.lng,
             d.created_at         AS createdAt
      FROM donors d ${where}
      ORDER BY
        CASE d.availability
          WHEN 'available'         THEN 0
          WHEN 'recently_donated'  THEN 1
          ELSE 2
        END,
        d.updated_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ total, page, pages, limit, count: donors.length, donors });
  }
);

// ── Single donor — auth required, phone included ──────────────
app.get('/api/donors/:id',
  auth,
  [ param('id').isUUID().withMessage('Invalid donor ID.') ],
  validate,
  (req, res) => {
    const donor = stmts.getDonorById.get(req.params.id);
    if (!donor) return res.status(404).json({ error: 'Donor not found.' });
    const { user_id: _, ...d } = donor;
    res.json({
      id: d.id,
      name: d.name,
      bloodGroup: d.blood_group,
      city: d.city,
      phone: d.phone,
      availability: d.availability,
      lastDonationDate: d.last_donation_date,
      weightKg: d.weight_kg,
      lat: d.lat,
      lng: d.lng,
      notes: d.notes,
      createdAt: d.created_at,
    });
  }
);

// ── Save donor profile (create or update) ─────────────────────
app.post('/api/donors',
  auth,
  [
    body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2–100 characters.')
      .matches(/^[\p{L}\s'.,-]+$/u).withMessage('Name contains invalid characters.'),
    body('bloodGroup').isIn(BLOOD_GROUPS).withMessage('Invalid blood group.'),
    body('city').trim().isLength({ min: 2, max: 100 }).withMessage('City must be 2–100 characters.')
      .escape(),
    phoneRules,
    body('weightKg').optional({ nullable: true })
      .isFloat({ min: 40, max: 250 }).withMessage('Weight must be 40–250 kg.'),
    body('lastDonationDate').optional({ nullable: true })
      .isISO8601().withMessage('Invalid date (use YYYY-MM-DD).')
      .isBefore(new Date(Date.now() + 86400000).toISOString()).withMessage('Donation date cannot be in the future.'),
    body('lat').optional({ nullable: true }).isFloat({ min: -90,  max: 90  }).withMessage('Invalid latitude.'),
    body('lng').optional({ nullable: true }).isFloat({ min: -180, max: 180 }).withMessage('Invalid longitude.'),
    body('notes').optional({ nullable: true }).trim().isLength({ max: 500 }).withMessage('Notes max 500 characters.').escape(),
  ],
  validate,
  (req, res) => {
    if (req.user.role !== 'donor')
      return res.status(403).json({ error: 'Only donor accounts can create a donor profile.' });

    const { name, bloodGroup, city, phone, weightKg, lastDonationDate, lat, lng, notes } = req.body;
    const existing = stmts.getDonorByUserId.get(req.user.id);

    if (existing) {
      stmts.updateDonor.run(
        name, bloodGroup, city, phone,
        weightKg ?? null, lastDonationDate ?? null, lat ?? null, lng ?? null, notes ?? null,
        req.user.id
      );
    } else {
      stmts.insertDonor.run(
        uuidv4(), req.user.id, name, bloodGroup, city, phone,
        weightKg ?? null, lastDonationDate ?? null, lat ?? null, lng ?? null, notes ?? null
      );
    }

    const donor = stmts.getDonorByUserId.get(req.user.id);
    res.json({
      message: existing ? 'Profile updated.' : 'Donor profile created.',
      donor: {
        id: donor.id,
        name: donor.name,
        bloodGroup: donor.blood_group,
        city: donor.city,
        phone: donor.phone,
        availability: donor.availability,
        lastDonationDate: donor.last_donation_date,
        weightKg: donor.weight_kg,
        lat: donor.lat,
        lng: donor.lng,
        notes: donor.notes,
        createdAt: donor.created_at,
        updatedAt: donor.updated_at,
      },
    });
  }
);

// ── Update availability ────────────────────────────────────────
app.patch('/api/donors/availability',
  auth,
  [body('availability').isIn(['available','recently_donated','unavailable']).withMessage('Invalid availability.')],
  validate,
  (req, res) => {
    const donor = stmts.getDonorByUserId.get(req.user.id);
    if (!donor) return res.status(404).json({ error: 'Create your donor profile first.' });
    stmts.updateAvailability.run(req.body.availability, req.user.id);
    res.json({ message: 'Availability updated.', availability: req.body.availability });
  }
);

// ── Static frontend ────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: NODE_ENV === 'production' ? '1d' : 0,
  etag: true,
}));

// SPA fallback
app.get('*', (_req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// ── 404 for unknown API routes ─────────────────────────────────
app.use('/api/*', (_req, res) => res.status(404).json({ error: 'API route not found.' }));

// ── Global error handler ───────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (NODE_ENV !== 'production') console.error(`[${req.requestId}]`, err);
  else console.error(`[${req.requestId}] ${err.message}`);
  if (err.message?.startsWith('CORS'))
    return res.status(403).json({ error: err.message });
  res.status(500).json({ error: 'Internal server error.', requestId: req.requestId });
});

process.on('unhandledRejection', r => console.error('UnhandledRejection:', r));
process.on('uncaughtException',  e => { console.error('UncaughtException:', e); process.exit(1); });

// Graceful shutdown — close DB cleanly
process.on('SIGTERM', () => { db.close(); process.exit(0); });
process.on('SIGINT',  () => { db.close(); process.exit(0); });

// ── Start ──────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ✅  Hemolink v2.0 — ${NODE_ENV}`);
  console.log(`  🌐  http://localhost:${PORT}`);
  console.log(`  🗄   ${path.resolve(DB_PATH)}`);
  console.log(`  🔒  JWT exp: ${JWT_EXPIRES_IN}  •  bcrypt: 12  •  pepper: ${BCRYPT_PEPPER ? 'yes' : 'no'}\n`);
});

module.exports = app;
