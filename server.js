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

// Log new parcel endpoint
app.post('/api/parcels', authenticateToken, async (req, res) => {
  const { awbNumber, recipientName, recipientUnit } = req.body;
  const user = req.user; // Decoded from the JWT token
  try {
    if (user.role !== 'guard') {
      return res.status(403).json({ msg: 'Only guards can log parcels' });
    }
    const result = await client.query(
      'INSERT INTO parcels (awb_number, recipient_name, recipient_unit) VALUES ($1, $2, $3) RETURNING *',
      [awbNumber, recipientName, recipientUnit]
    );
    res.json({ msg: 'Parcel logged successfully', parcel: result.rows[0] });
  } catch (err) {
    res.status(500).json({ msg: 'Failed to log parcel' });
  }
});

// Collect parcel endpoint (placeholder for now)
app.post('/api/parcels/collect', authenticateToken, async (req, res) => {
  const { awbNumber } = req.body;
  const user = req.user; // Decoded from the JWT token
  try {
    const result = await client.query(
      'UPDATE parcels SET collected_at = CURRENT_TIMESTAMP, collected_by = $1 WHERE awb_number = $2 AND collected_at IS NULL RETURNING *',
      [user.id, awbNumber]
    );
    if (result.rows.length > 0) {
      res.json({ msg: 'Parcel collected successfully', parcel: result.rows[0] });
    } else {
      res.status(404).json({ msg: 'Parcel not found or already collected' });
    }
  } catch (err) {
    res.status(500).json({ msg: 'Failed to collect parcel' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
