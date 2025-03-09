import 'dotenv/config';
import express from 'express';
import pg from 'pg';
const { Client } = pg;
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors({ origin: 'https://parcel-app-7mbi.onrender.com' }));

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

// Register endpoint
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

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await client.query(
      'SELECT * FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const token = jwt.sign({ id: user.id, role: user.role || 'resident' }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, role: user.role || 'resident' });
    } else {
      res.status(401).json({ msg: 'Invalid email or password' });
    }
  } catch (err) {
    res.status(500).json({ msg: 'Login failed' });
  }
});

// Protect parcel routes with authentication (placeholder for now)
app.use('/api/parcels', authenticateToken, (req, res) => {
  res.status(501).json({ msg: 'Not implemented yet' });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
