const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-super-secret-key-change-this-in-production';

const db = new Database('employees.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    department TEXT NOT NULL,
    salary REAL NOT NULL
  );
`);

const adminExists = db.prepare('SELECT * FROM users WHERE username =?').get('admin');
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password) VALUES (?,?)').run('admin', hashedPassword);
}

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

app.post('/api/register', [
  body('username').notEmpty(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (username, password) VALUES (?,?)').run(username, hashedPassword);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Username already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username =?').get(username);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
  res.json({ token });
});

app.get('/api/employees', authenticateToken, (req, res) => {
  const employees = db.prepare('SELECT * FROM employees').all();
  res.json(employees);
});

app.post('/api/employees', authenticateToken, [
  body('name').notEmpty(),
  body('email').isEmail(),
  body('department').notEmpty(),
  body('salary').isNumeric()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, email, department, salary } = req.body;
  try {
    const result = db.prepare('INSERT INTO employees (name, email, department, salary) VALUES (?,?,?,?)').run(name, email, department, salary);
    res.status(201).json({ id: result.lastInsertRowid,...req.body });
  } catch (error) {
    res.status(400).json({ message: 'Email already exists' });
  }
});

app.put('/api/employees/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { name, email, department, salary } = req.body;
  const result = db.prepare('UPDATE employees SET name =?, email =?, department =?, salary =? WHERE id =?').run(name, email, department, salary, id);
  if (result.changes === 0) return res.status(404).json({ message: 'Employee not found' });
  res.json({ id,...req.body });
});

app.delete('/api/employees/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const result = db.prepare('DELETE FROM employees WHERE id =?').run(id);
  if (result.changes === 0) return res.status(404).json({ message: 'Employee not found' });
  res.json({ message: 'Employee deleted successfully' });
});

// EXPRESS 5 FIX: Use regex, not string
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
