const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const JWT_SECRET = 'your_super_secret_key_123';
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new Database('employees.db');

// Create tables
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
    position TEXT NOT NULL,
    salary REAL NOT NULL
  );
`);

// Create default admin
const hashedPassword = bcrypt.hashSync('admin123', 10);
const insertUser = db.prepare(`INSERT OR IGNORE INTO users (username, password) VALUES (?,?)`);
insertUser.run('admin', hashedPassword);

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Login route
app.post('/api/login', [
  body('username').notEmpty().withMessage('Username required'),
  body('password').notEmpty().withMessage('Password required')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  
  try {
    const user = db.prepare('SELECT * FROM users WHERE username =?').get(username);
    
    if (!user ||!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, message: 'Login successful' });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Get all employees
app.get('/api/employees', authenticateToken, (req, res) => {
  try {
    const employees = db.prepare('SELECT * FROM employees ORDER BY id DESC').all();
    res.json(employees);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});

// Get single employee
app.get('/api/employees/:id', authenticateToken, (req, res) => {
  try {
    const employee = db.prepare('SELECT * FROM employees WHERE id =?').get(req.params.id);
    if (!employee) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    res.json(employee);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch employee' });
  }
});

// Create employee
app.post('/api/employees', authenticateToken, [
  body('name').notEmpty().withMessage('Name required'),
  body('email').isEmail().withMessage('Valid email required'),
  body('position').notEmpty().withMessage('Position required'),
  body('salary').isFloat({ min: 0 }).withMessage('Salary must be positive')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, position, salary } = req.body;
  
  try {
    const result = db.prepare('INSERT INTO employees (name, email, position, salary) VALUES (?,?,?,?)')
     .run(name, email, position, salary);
    
    const newEmployee = db.prepare('SELECT * FROM employees WHERE id =?').get(result.lastInsertRowid);
    res.status(201).json(newEmployee);
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Failed to create employee' });
  }
});

// Update employee
app.put('/api/employees/:id', authenticateToken, [
  body('name').notEmpty().withMessage('Name required'),
  body('email').isEmail().withMessage('Valid email required'),
  body('position').notEmpty().withMessage('Position required'),
  body('salary').isFloat({ min: 0 }).withMessage('Salary must be positive')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, position, salary } = req.body;
  
  try {
    const result = db.prepare('UPDATE employees SET name =?, email =?, position =?, salary =? WHERE id =?')
     .run(name, email, position, salary, req.params.id);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    
    const updatedEmployee = db.prepare('SELECT * FROM employees WHERE id =?').get(req.params.id);
    res.json(updatedEmployee);
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Failed to update employee' });
  }
});

// Delete employee
app.delete('/api/employees/:id', authenticateToken, (req, res) => {
  try {
    const result = db.prepare('DELETE FROM employees WHERE id =?').run(req.params.id);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    
    res.json({ message: 'Employee deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete employee' });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
