const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;
const SECRET = 'supersecretkey';

app.use(cors());
app.use(express.json({limit: '10mb'})); // allow large payloads for signature

const db = new sqlite3.Database('./db.sqlite3');

// DB setup
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    phone TEXT,
    email TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS pickups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    items TEXT,
    datetime TEXT,
    signature TEXT
  )`);
  // Create a default admin if not exists
  db.get(`SELECT * FROM users WHERE username = ?`, ['admin'], (err, row) => {
    if (!row) {
      bcrypt.hash('adminpass', 10, (err, hash) => {
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, ['admin', hash, 'admin']);
      });
    }
  });
});

// Auth middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Auth routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        const token = jwt.sign({ username: user.username, role: user.role }, SECRET);
        res.json({ token });
      } else {
        res.status(401).json({ message: 'Invalid credentials' });
      }
    });
  });
});

// Get contact by name (for autofill)
app.get('/api/contact/:name', authenticateToken, (req, res) => {
  db.get(`SELECT * FROM contacts WHERE name = ?`, [req.params.name], (err, contact) => {
    res.json(contact || {});
  });
});

// Add/Update contact info
app.post('/api/contact', authenticateToken, (req, res) => {
  const { name, phone, email } = req.body;
  db.run(
    `INSERT INTO contacts (name, phone, email) VALUES (?, ?, ?)
     ON CONFLICT(name) DO UPDATE SET phone=excluded.phone, email=excluded.email`,
    [name, phone, email],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Add pickup (includes signature, items, datetime, name)
app.post('/api/pickup', authenticateToken, (req, res) => {
  const { name, items, datetime, signature } = req.body;
  db.run(
    `INSERT INTO pickups (name, items, datetime, signature) VALUES (?, ?, ?, ?)`,
    [name, items, datetime, signature],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Get pickups (history)
app.get('/api/pickups', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM pickups ORDER BY datetime DESC`, [], (err, rows) => {
    res.json(rows);
  });
});

// Search pickups by name
app.get('/api/pickups/:name', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM pickups WHERE name = ? ORDER BY datetime DESC`, [req.params.name], (err, rows) => {
    res.json(rows);
  });
});

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
