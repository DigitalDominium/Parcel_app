require('dotenv').config();
const express = require('express');
const { Client } = require('pg'); // Use pg instead of mongoose
const path = require('path');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // Add cors for front-end communication
const app = express();

app.use(express.json()); // To parse JSON bodies
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files
app.use(cors({ origin: 'https://your-static-site-url.onrender.com' })); // Replace with your Static Site URL

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ msg: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// Initialize PostgreSQL client
const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
client.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.log('PostgreSQL error:', err));

// Load routes (ensure you have an auth.js file or remove this if not needed yet)
// const authRoutes = require('./routes/auth');
// app.use('/api/auth', authRoutes);

// Example API route (replace with your actual routes)
app.post('/api/auth/register', async (req, res) => {
  const { name, unitNumber, email, password } = req.body;
  try {
    await client.query(
      'INSERT INTO users (name, unit_number, email, password) VALUES ($1, $2, $3, $4)',
      [name, unitNumber, email, password] // Use bcrypt for password hashing in production
    );
    res.json({ msg: 'Registration successful' });
  } catch (err) {
    res.status(500).json({ msg: 'Registration failed' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
