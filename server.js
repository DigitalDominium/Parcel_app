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
app.use(cors({ origin: 'https://parcel-app-7mbi.onrender.com' })); 

// Database Connection
const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
client.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.log('PostgreSQL error:', err));

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ msg: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ msg: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

// **Register API**
app.post('/api/auth/register', async (req, res) => {
  const { name, unitNumber, email, password } = req.body;

  try {
    await client.query(
      'INSERT INTO users (name, unit_number, email, password, role) VALUES ($1, $2, $3, $4, $5)',
      [name, unitNumber, email, password, 'resident']
    );
    res.json({ msg: 'Registration successful' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ msg: 'Registration failed' });
  }
});

// **Login API**
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
    console.error('Error logging in:', err);
    res.status(500).json({ msg: 'Login failed' });
  }
});

// **Retrieve Parcels API (Guards See All, Residents See Their Own)**
app.get('/api/parcels', authenticateToken, async (req, res) => {
    console.log("🟢 Fetching Parcels for User ID:", req.user.id);

    const user = req.user;
    try {
        let result;
        if (user.role === 'guard') {
            result = await client.query('SELECT * FROM parcels'); // ✅ Guards get all parcels
        } else {
            // ✅ Residents only get UNCOLLECTED parcels
            const userResult = await client.query('SELECT unit_number FROM users WHERE id = $1', [user.id]);
            const unitNumber = userResult.rows[0]?.unit_number;

            result = await client.query(
                'SELECT * FROM parcels WHERE recipient_unit = $1 AND collected_at IS NULL',
                [unitNumber]
            );
        }

        res.json(result.rows);
    } catch (err) {
        console.error('Error retrieving parcels:', err);
        res.status(500).json({ msg: 'Failed to retrieve parcels' });
    }
});

// **Log New Parcel API (Only for Guards)**
app.post('/api/parcels', authenticateToken, async (req, res) => {
    const { awbNumber, recipientName, recipientUnit } = req.body;

    try {
        // Check if AWB number already exists
        const checkResult = await client.query('SELECT * FROM parcels WHERE awb_number = $1', [awbNumber]);

        if (checkResult.rows.length > 0) {
            return res.status(409).json({ msg: 'Error: This AWB number is already logged.' });
        }

        // Insert new parcel if AWB does not exist
        const result = await client.query(
            'INSERT INTO parcels (awb_number, recipient_name, recipient_unit, delivered_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) RETURNING *',
            [awbNumber, recipientName, recipientUnit]
        );

        res.json({ msg: 'Parcel logged successfully', parcel: result.rows[0] });

    } catch (err) {
        console.error('Error logging parcel:', err);
        res.status(500).json({ msg: 'Failed to log parcel. Please try again.' });
    }
});

// **Collect Parcel API (Residents Only)**
app.post('/api/parcels/collect', authenticateToken, async (req, res) => {
  const { awbNumber } = req.body;
  const user = req.user;

  if (!awbNumber) {
    return res.status(400).json({ msg: 'AWB Number is required' });
  }

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
    console.error('Error collecting parcel:', err);
    res.status(500).json({ msg: 'Failed to collect parcel' });
  }
});

// **Start Server**
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
