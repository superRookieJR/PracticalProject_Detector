const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();  // SQLite
const app = express();
const PORT = 4000;

// Connect to SQLite database (file-based)
const db = new sqlite3.Database('./demo.db', (err) => {
  if (err) {
    console.error('Error opening database', err);
  } else {
    console.log('Connected to SQLite database.');
    
    // Create a table for demo if not exists
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      password TEXT
    )`);
  }
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Default route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Dangerous raw SQL execution
app.post('/execute', (req, res) => {
  const { command } = req.body;
  console.log('Received command:', command);

  // ⚠️ Directly execute whatever command is sent (VULNERABLE)
  db.all(command, [], (err, rows) => {
    if (err) {
      console.error('Query error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Query executed successfully', results: rows });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});