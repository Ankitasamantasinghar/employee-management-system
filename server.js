const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000; // ← Added for deployment
const JWT_SECRET = 'your_super_secret_key_change_this';

app.use(express.json());
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database('./employees.db', (err) => {
    if (err) console.error(err.message);
    else console.log('Connected to SQLite database.');
});

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        position TEXT NOT NULL,
        salary REAL NOT NULL
    )`);

    // Create default admin if not exists
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?,?)`, 
        ['admin', hashedPassword]);
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token required' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Login route
app.post('/api/login', [
    body('username').notEmpty(),
    body('password').notEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username =?', [username], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });
        
        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
        
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Validation rules
const employeeValidation = [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email required'),
    body('position').trim().notEmpty().withMessage('Position is required'),
    body('salary').isFloat({ min: 0 }).withMessage('Salary must be a positive number')
];

// CRUD Routes - All Protected
app.get('/api/employees', authenticateToken, (req, res) => {
    db.all('SELECT * FROM employees', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/employees', authenticateToken, employeeValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, position, salary } = req.body;
    db.run('INSERT INTO employees (name, email, position, salary) VALUES (?,?,?,?)',
        [name, email, position, salary],
        function(err) {
            if (err) return res.status(400).json({ error: 'Email already exists' });
            res.json({ id: this.lastID, name, email, position, salary });
        }
    );
});

app.put('/api/employees/:id', authenticateToken, employeeValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, position, salary } = req.body;
    db.run('UPDATE employees SET name =?, email =?, position =?, salary =? WHERE id =?',
        [name, email, position, salary, req.params.id],
        function(err) {
            if (err) return res.status(400).json({ error: 'Email already exists' });
            if (this.changes === 0) return res.status(404).json({ error: 'Employee not found' });
            res.json({ id: req.params.id, name, email, position, salary });
        }
    );
});

app.delete('/api/employees/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM employees WHERE id =?', req.params.id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Employee not found' });
        res.json({ message: 'Employee deleted' });
    });
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});