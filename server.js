const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'poop-tracker-secret-change-in-production';
const DATA_FILE = path.join(__dirname, 'data.json');

// ── CORS ───────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── SIMPLE JSON "DATABASE" ─────────────────────────────────────────
// On Render free tier, disk is ephemeral — use Render's free PostgreSQL
// or an external DB for production persistence. This JSON store is great
// for getting started and testing.
function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return { users: {}, logs: [] };
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { users: {}, logs: [] };
  }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ── AUTH MIDDLEWARE ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.username = decoded.username;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── ROUTES ─────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: '💩 Poop Tracker API' });
});

// Register
app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || username.length < 2) return res.status(400).json({ error: 'Username must be at least 2 characters' });
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });

  const data = loadData();
  const key = username.toLowerCase();
  if (data.users[key]) return res.status(409).json({ error: 'Username already taken!' });

  const hash = await bcrypt.hash(password, 10);
  data.users[key] = { displayName: username, password: hash };
  saveData(data);

  const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username });
});

// Login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const data = loadData();
  const found = data.users[username.toLowerCase()];
  if (!found) return res.status(401).json({ error: 'Wrong username or password 🚫' });

  const match = await bcrypt.compare(password, found.password);
  if (!match) return res.status(401).json({ error: 'Wrong username or password 🚫' });

  const token = jwt.sign({ username: found.displayName }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: found.displayName });
});

// Log a poop
app.post('/logs', requireAuth, (req, res) => {
  const data = loadData();
  const now = Date.now();
  const month = monthKey(now);
  data.logs.push({ user: req.username, month, ts: now });
  saveData(data);
  res.json({ success: true, ts: now });
});

// Get my logs for current month
app.get('/logs/me', requireAuth, (req, res) => {
  const data = loadData();
  const month = monthKey(Date.now());
  const myLogs = data.logs.filter(l => l.user === req.username && l.month === month);
  res.json(myLogs);
});

// Get leaderboard for current month
app.get('/logs/leaderboard', requireAuth, (req, res) => {
  const data = loadData();
  const month = monthKey(Date.now());
  const monthLogs = data.logs.filter(l => l.month === month);
  const counts = {};
  monthLogs.forEach(l => { counts[l.user] = (counts[l.user] || 0) + 1; });
  if (!counts[req.username]) counts[req.username] = 0;
  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));
  res.json(sorted);
});

// ── HELPERS ────────────────────────────────────────────────────────
function monthKey(ts) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

app.listen(PORT, () => {
  console.log(`💩 Poop Tracker API running on port ${PORT}`);
});
