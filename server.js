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

function ensureBookColumns() {
  const res = db.exec('PRAGMA table_info(books)');
  const cols = new Set();
  if (res && res[0] && res[0].values) {
    for (const row of res[0].values) {
      cols.add(row[1]);
    }
  }
  const statements = [];
  if (!cols.has('borrowed_until')) statements.push('ALTER TABLE books ADD COLUMN borrowed_until DATETIME');
  if (!cols.has('borrowed_by')) statements.push('ALTER TABLE books ADD COLUMN borrowed_by INTEGER');
  if (!cols.has('reserved_until')) statements.push('ALTER TABLE books ADD COLUMN reserved_until DATETIME');
  if (!cols.has('reserved_by')) statements.push('ALTER TABLE books ADD COLUMN reserved_by INTEGER');
  if (statements.length) {
    for (const stmt of statements) db.run(stmt);
    exportAndSave();
  }
}

function parseDate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function isFutureDate(value) {
  const date = parseDate(value);
  return date ? date.getTime() > Date.now() : false;
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
      borrowed_until DATETIME,
      borrowed_by INTEGER,
      reserved_until DATETIME,
      reserved_by INTEGER,
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
    // sample books (some with mock borrowed data for demonstration)
    const samples = [
      ['Der kleine Prinz','Antoine de Saint-Exupéry','Kinderbuch','978315000001', null, null, null, null],
      ['Faust','Johann Wolfgang von Goethe','Drama','978315000002', null, null, null, null],
      ['Clean Code','Robert C. Martin','Programmierung','9780132350884', new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), 1, null, null],
      ['Eloquent JavaScript','Marijn Haverbeke','Programmierung','9781593279509', new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(), 1, null, null],
      ['Die Verwandlung','Franz Kafka','Novelle','978315000005', null, null, null, null]
    ];
    for (const it of samples) {
      db.run('INSERT INTO books (title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', it);
    }
    exportAndSave();
  }
  // ensure unique ISBN index exists (allowing multiple NULLs)
  try {
    db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_books_isbn ON books(isbn);');
  } catch (e) {}
  ensureBookColumns();

  // Insert sample books if table is empty
  function insertSampleBooks() {
    const samples = [
      ['Der kleine Prinz','Antoine de Saint-Exupéry','Kinderbuch','978315000001', null, null, null, null],
      ['Faust','Johann Wolfgang von Goethe','Drama','978315000002', null, null, null, null],
      ['Clean Code','Robert C. Martin','Programmierung','9780132350884', new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), 1, null, null],
      ['Eloquent JavaScript','Marijn Haverbeke','Programmierung','9781593279509', new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(), 1, null, null],
      ['Die Verwandlung','Franz Kafka','Novelle','978315000005', null, null, null, null]
    ];
    for (const it of samples) {
      db.run('INSERT INTO books (title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', it);
    }
    exportAndSave();
  }

  // Check if books table is empty and populate if needed
  const bookCount = getRow('SELECT COUNT(*) as cnt FROM books');
  if (bookCount && bookCount.cnt === 0) {
    insertSampleBooks();
  }

  // Routes
  app.get('/', (req, res) => {
    res.send('Bibliotheks-API läuft! (sql.js)');
  });

  app.get('/books', (req, res) => {
    try {
      const rows = allRows('SELECT id, title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by, created_at FROM books ORDER BY id');
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

  // Reserve a book (authenticated users). 2 weeks if available, or 1 week after due date if borrowed.
  app.post('/books/:id/reserve', authMiddleware, (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    try {
      const book = getRow('SELECT id, borrowed_until, reserved_until, reserved_by FROM books WHERE id = ?', [id]);
      if (!book) return res.status(404).json({ error: 'Book not found' });

      const reservedActive = isFutureDate(book.reserved_until);
      if (reservedActive && book.reserved_by && book.reserved_by !== req.user.id) {
        return res.status(409).json({ error: 'Book already reserved' });
      }

      let newReservedUntil;
      if (isFutureDate(book.borrowed_until)) {
        const borrowedUntil = parseDate(book.borrowed_until);
        newReservedUntil = new Date(borrowedUntil.getTime() + 7 * 24 * 60 * 60 * 1000);
      } else {
        newReservedUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      }

      runStmt('UPDATE books SET reserved_until = ?, reserved_by = ? WHERE id = ?', [newReservedUntil.toISOString(), req.user.id, id]);
      const updated = getRow('SELECT id, title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by, created_at FROM books WHERE id = ?', [id]);
      res.json(updated);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'DB error' });
    }
  });

  // Borrow a book (admin only). 2 weeks from now.
  app.post('/books/:id/borrow', authMiddleware, adminMiddleware, (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    try {
      const book = getRow('SELECT id, borrowed_until, reserved_until, reserved_by FROM books WHERE id = ?', [id]);
      if (!book) return res.status(404).json({ error: 'Book not found' });

      if (isFutureDate(book.borrowed_until)) {
        return res.status(409).json({ error: 'Book already borrowed' });
      }

      const reservedActive = isFutureDate(book.reserved_until);
      if (reservedActive && book.reserved_by && book.reserved_by !== req.user.id) {
        return res.status(409).json({ error: 'Book reserved by another user' });
      }

      const borrowedUntil = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);
      const clearReservation = !reservedActive || book.reserved_by === req.user.id;
      const reservedUntil = clearReservation ? null : book.reserved_until;
      const reservedBy = clearReservation ? null : book.reserved_by;

      runStmt(
        'UPDATE books SET borrowed_until = ?, borrowed_by = ?, reserved_until = ?, reserved_by = ? WHERE id = ?',
        [borrowedUntil.toISOString(), req.user.id, reservedUntil, reservedBy, id]
      );

      const updated = getRow('SELECT id, title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by, created_at FROM books WHERE id = ?', [id]);
      res.json(updated);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'DB error' });
    }
  });

  // Return a book (admin only).
  app.post('/books/:id/return', authMiddleware, adminMiddleware, (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    try {
      const book = getRow('SELECT id, borrowed_until, reserved_until, reserved_by FROM books WHERE id = ?', [id]);
      if (!book) return res.status(404).json({ error: 'Book not found' });

      const reservedActive = isFutureDate(book.reserved_until);
      const reservedUntil = reservedActive ? book.reserved_until : null;
      const reservedBy = reservedActive ? book.reserved_by : null;

      runStmt(
        'UPDATE books SET borrowed_until = NULL, borrowed_by = NULL, reserved_until = ?, reserved_by = ? WHERE id = ?',
        [reservedUntil, reservedBy, id]
      );

      const updated = getRow('SELECT id, title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by, created_at FROM books WHERE id = ?', [id]);
      res.json(updated);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'DB error' });
    }
  });

  // Cancel a reservation (authenticated user, only their own).
  app.post('/books/:id/unreserve', authMiddleware, (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    try {
      const book = getRow('SELECT id, reserved_by FROM books WHERE id = ?', [id]);
      if (!book) return res.status(404).json({ error: 'Book not found' });

      if (!book.reserved_by || book.reserved_by !== req.user.id) {
        return res.status(403).json({ error: 'Cannot unreserve reservation of another user' });
      }

      runStmt('UPDATE books SET reserved_until = NULL, reserved_by = NULL WHERE id = ?', [id]);

      const updated = getRow('SELECT id, title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by, created_at FROM books WHERE id = ?', [id]);
      res.json(updated);
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

  // Admin endpoint to reset sample books with mock borrowed data
  app.post('/admin/reset-sample-books', authMiddleware, adminMiddleware, (req, res) => {
    try {
      runStmt('DELETE FROM books');
      insertSampleBooks();
      const books = allRows('SELECT id, title, author, genre, isbn, borrowed_until, borrowed_by, reserved_until, reserved_by, created_at FROM books ORDER BY id');
      res.json({ message: 'Sample books reset', books });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'DB error' });
    }
  });

  app.listen(PORT, () => {
    console.log(`Server läuft auf http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize sql.js', err);
  process.exit(1);
});