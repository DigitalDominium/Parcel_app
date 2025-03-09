import 'dotenv/config';
import express from 'express';
import pg from 'pg'; // Updated import
const { Client } = pg; // Extract Client from the default export
import path from 'path';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors({ origin: 'https://parcel-app-7mbi.onrender.com' })); // Replace with your Static Site URL

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ msg: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
client.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.log('PostgreSQL error:', err));

app.post('/api/auth/register', async (req, res) => {
  const { name, unitNumber, email, password } = req.body;
  try {
    await client.query(
      'INSERT INTO users (name, unit_number, email, password) VALUES ($1, $2, $3, $4)',
      [name, unitNumber, email, password]
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
