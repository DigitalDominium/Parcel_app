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

  console.log("Received Token:", token); // Debugging Token

  if (!token) {
    return res.status(401).json({ msg: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log("Token Verification Failed:", err);
      return res.status(403).json({ msg: 'Invalid token' });
    }
    req.user = decoded;
    console.log("Decoded User:", req.user); // Debugging User Info
    next();
  });
};

// **Register API**
app.post('/api/auth/register', async (req, res) => {
  const { name, unitNumber, email, password } = req.body;
  console.log("Register Request Body:", req.body); // Debugging

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
  console.log("Login Request Body:", req.body); // Debugging

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

// **Retrieve Parcels API**
app.get('/api/parcels', authenticateToken, async (req, res) => {
  console.log("User Role:", req.user.role); // Debugging Role
  const user = req.user;

  try {
    let result;
    if (user.role === 'guard') {
      result = await client.query('SELECT * FROM parcels');
    } else {
      const userResult = await client.query('SELECT unit_number FROM users WHERE id = $1', [user.id]);
      const unitNumber = userResult.rows[0]?.unit_number;
      result = await client.query('SELECT * FROM parcels WHERE recipient_unit = $1', [unitNumber]);
    }
    res.json(result.rows);
  } catch (err) {
    console.error('Error retrieving parcels:', err);
    res.status(500).json({ msg: 'Failed to retrieve parcels' });
  }
});

// **Log New Parcel API**
app.post('/api/parcels', authenticateToken, async (req, res) => {
    console.log("🟢 Received Request Body:", req.body); // Debugging

    const { awbNumber, recipientName, unitNumber } = req.body; // ✅ Change recipientUnit to unitNumber

    if (!awbNumber || !recipientName || !unitNumber) {
        console.log("🔴 Missing Fields:", { awbNumber, recipientName, unitNumber }); // ✅ Debugging
        return res.status(400).json({ msg: 'All fields (AWB Number, Recipient Name, Recipient Unit) are required' });
    }

    const user = req.user;
    if (user.role !== 'guard') {
        return res.status(403).json({ msg: 'Only guards can log parcels' });
    }

    try {
        const result = await client.query(
            'INSERT INTO parcels (awb_number, recipient_name, recipient_unit) VALUES ($1, $2, $3) RETURNING *',
            [awbNumber, recipientName, unitNumber] // ✅ Use unitNumber here
        );
        res.json({ msg: 'Parcel logged successfully', parcel: result.rows[0] });
    } catch (err) {
        console.error('Error logging parcel:', err);
        res.status(500).json({ msg: 'Failed to log parcel' });
    }
});

// **Collect Parcel API**
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
