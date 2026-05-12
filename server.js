const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');

const app = express();
const JWT_SECRET = 'change-this-secret-key';
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new sqlite3.Database('./employees.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, position TEXT NOT NULL, salary REAL NOT NULL)`);
  const hashedPwd = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?,?)`, ['admin', hashedPwd]);
});

const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } 
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

const employeeValidation = [
  body('name').notEmpty().withMessage('Name required'), 
  body('email').isEmail().withMessage('Valid email required'), 
  body('position').notEmpty().withMessage('Position required'), 
  body('salary').isFloat({ min: 0 }).withMessage('Salary must be positive')
];

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username =?', [username], async (err, user) => {
    if (!user ||!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});

app.post('/api/employees', authenticate, employeeValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, email, position, salary } = req.body;
  db.run('INSERT INTO employees (name, email, position, salary) VALUES (?,?,?,?)', [name, email, position, salary], function(err) {
    if (err) return res.status(400).json({ error: 'Email already exists' });
    res.json({ id: this.lastID, name, email, position, salary });
  });
});

app.get('/api/employees', authenticate, (req, res) => {
  db.all('SELECT * FROM employees', (err, rows) => res.json(rows));
});

app.put('/api/employees/:id', authenticate, employeeValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, email, position, salary } = req.body;
  db.run('UPDATE employees SET name=?, email=?, position=?, salary=? WHERE id=?', [name, email, position, salary, req.params.id], function(err) {
    if (this.changes === 0) return res.status(404).json({ error: 'Employee not found' });
    res.json({ message: 'Updated' });
  });
});

app.delete('/api/employees/:id', authenticate, (req, res) => {
  db.run('DELETE FROM employees WHERE id=?', [req.params.id], function(err) {
    if (this.changes === 0) return res.status(404).json({ error: 'Employee not found' });
    res.json({ message: 'Deleted' });
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));