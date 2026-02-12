require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const initSqlJs = require('sql.js');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const dbFile = process.env.SQLITE_FILE || './db/database.sqlite';
let SQL;
let db;

function exportAndSave() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.mkdirSync('./db', { recursive: true });
  fs.writeFileSync(dbFile, buffer);
}

function signToken(user) {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, secret, { expiresIn: '8h' });
}

function allRows(stmtSql, params = []) {
  const stmt = db.prepare(stmtSql);
  const rows = [];
  try {
    stmt.bind(params);
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
  } finally {
    stmt.free();
  }
  return rows;
}

function getRow(stmtSql, params = []) {
  const stmt = db.prepare(stmtSql);
  try {
    stmt.bind(params);
    if (stmt.step()) {
      return stmt.getAsObject();
    }
    return null;
  } finally {
    stmt.free();
  }
}

function runStmt(stmtSql, params = []) {
  // use db.run for sql.js which accepts parameters
  if (params && params.length) {
    db.run(stmtSql, params);
  } else {
    db.run(stmtSql);
  }
  exportAndSave();
}

function insertAndGetId(stmtSql, params = []) {
  if (params && params.length) db.run(stmtSql, params);
  else db.run(stmtSql);
  // persist DB to file after insert
  exportAndSave();
  const res = db.exec('SELECT last_insert_rowid() as id');
  if (res && res[0] && res[0].values && res[0].values[0]) return res[0].values[0][0];
  return null;
}

function findUserByUsername(username) {
  return getRow('SELECT * FROM users WHERE username = ?', [username]);
}

initSqlJs().then((SQLlib) => {
  SQL = SQLlib;
  // load or create DB
  if (fs.existsSync(dbFile)) {
    const filebuffer = fs.readFileSync(dbFile);
    db = new SQL.Database(filebuffer);
  } else {
    db = new SQL.Database();
    // create schema
    db.run(`CREATE TABLE IF NOT EXISTS books (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      author TEXT NOT NULL,
      genre TEXT,
      isbn TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`);
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`);
    // ensure unique ISBNs (NULLs allowed)
    try {
      db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_books_isbn ON books(isbn);');
    } catch (e) {
      // ignore if index fails for any reason
    }
    // sample books
    const samples = [
      ['Der kleine Prinz','Antoine de Saint-Exupéry','Kinderbuch','978315000001'],
      ['Faust','Johann Wolfgang von Goethe','Drama','978315000002'],
      ['Clean Code','Robert C. Martin','Programmierung','9780132350884'],
      ['Eloquent JavaScript','Marijn Haverbeke','Programmierung','9781593279509'],
      ['Die Verwandlung','Franz Kafka','Novelle','978315000005']
    ];
    for (const it of samples) {
      db.run('INSERT INTO books (title, author, genre, isbn) VALUES (?, ?, ?, ?)', it);
    }
    exportAndSave();
  }
  // ensure unique ISBN index exists (allowing multiple NULLs)
  try {
    db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_books_isbn ON books(isbn);');
  } catch (e) {}

  // Routes
  app.get('/', (req, res) => {
    res.send('Bibliotheks-API läuft! (sql.js)');
  });

  app.get('/books', (req, res) => {
    try {
      const rows = allRows('SELECT id, title, author, genre, isbn, created_at FROM books ORDER BY id');
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'DB error' });
    }
  });

  function adminMiddleware(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'Missing Authorization' });
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  }

  function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Missing Authorization' });
    const parts = header.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Bad Authorization format' });
    const token = parts[1];
    try {
      const secret = process.env.JWT_SECRET || 'dev-secret';
      const payload = jwt.verify(token, secret);
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }

  // Add book (admin only). title, author and isbn are required. Prevent duplicate ISBNs.
  app.post('/books', authMiddleware, adminMiddleware, (req, res) => {
    const { title, author, genre, isbn } = req.body;
    if (!title || !author || !isbn) return res.status(400).json({ error: 'title, author and isbn required' });
    try {
      const existing = getRow('SELECT id FROM books WHERE isbn = ?', [isbn]);
      if (existing) return res.status(409).json({ error: 'Book with this ISBN already exists' });
      const id = insertAndGetId('INSERT INTO books (title, author, genre, isbn) VALUES (?, ?, ?, ?)', [title, author, genre || null, isbn || null]);
      const row = getRow('SELECT id, title, author, genre, isbn, created_at FROM books WHERE id = ?', [id]);
      res.status(201).json(row);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'DB error' });
    }
  });

  // Delete book (admin only)
  app.delete('/books/:id', authMiddleware, adminMiddleware, (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    try {
      runStmt('DELETE FROM books WHERE id = ?', [id]);
      res.status(204).send();
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'DB error' });
    }
  });

  app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    try {
      const user = findUserByUsername(username);
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
      const ok = bcrypt.compareSync(password, user.password);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
      const token = signToken(user);
      res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Register endpoint: create a new user (role optional)
  app.post('/auth/register', (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    try {
      const existing = findUserByUsername(username);
      if (existing) return res.status(400).json({ error: 'User already exists' });
      const hash = bcrypt.hashSync(password, 10);
      runStmt('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hash, role || 'user']);
      const user = getRow('SELECT id, username, role FROM users WHERE username = ?', [username]);
      const token = signToken(user);
      res.json({ token, user });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/auth/setup', (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    try {
      const row = getRow('SELECT COUNT(*) as cnt FROM users');
      if (row && row.cnt > 0) return res.status(400).json({ error: 'Users already exist' });
      const hash = bcrypt.hashSync(password, 10);
      runStmt('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hash, role || 'admin']);
      const user = getRow('SELECT id, username, role FROM users WHERE username = ?', [username]);
      const token = signToken(user);
      res.json({ token, user });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.listen(PORT, () => {
    console.log(`Server läuft auf http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize sql.js', err);
  process.exit(1);
});