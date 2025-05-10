import 'dotenv/config';
import express from 'express';
import pg from 'pg';
const { Client } = pg;
import jwt from 'jsonwebtoken';
import cors from 'cors';
import bcrypt from 'bcrypt';

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

// Role-Based Middleware
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ msg: `Access restricted to ${roles.join(', ')} roles` });
    }
    next();
  };
};

// **Register API**
app.post('/api/auth/register', async (req, res) => {
  const { name, unitNumber, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ msg: 'Name, email, and password are required' });
  }

  try {
    const role = email === 'admin@example.com' ? 'admin' : (unitNumber === 'N/A' ? 'guard' : 'resident');
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

    await client.query(
      'INSERT INTO users (name, unit_number, email, password, role) VALUES ($1, $2, $3, $4, $5)',
      [name, unitNumber || null, email, hashedPassword, role]
    );
    res.json({ msg: 'Registration successful' });
  } catch (err) {
    console.error('Error registering user:', err);
    if (err.code === '23505') { // PostgreSQL unique constraint violation
      res.status(409).json({ msg: 'Email already exists' });
    } else {
      res.status(500).json({ msg: 'Registration failed' });
    }
  }
});

// **Login API**
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ msg: 'Email and password are required' });
  }

  try {
    const result = await client.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ msg: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password); // Compare hashed password
    if (!isMatch) {
      return res.status(401).json({ msg: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role, name: user.name });
  } catch (err) {
    console.error('Error logging in:', err);
    res.status(500).json({ msg: 'Login failed' });
  }
});

// **Admin Routes**
// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, restrictTo('admin'), async (req, res) => {
  try {
    const result = await client.query('SELECT id, name, email, unit_number, role FROM users');
    res.json(result.rows);
  } catch (err) {
    console.error('Error retrieving users:', err);
    res.status(500).json({ msg: 'Failed to retrieve users' });
  }
});

// Add a new user (admin only)
app.post('/api/admin/users', authenticateToken, restrictTo('admin'), async (req, res) => {
  const { name, email, password, unitNumber, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ msg: 'Name, email, password, and role are required' });
  }

  try {
    const checkResult = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (checkResult.rows.length > 0) {
      return res.status(409).json({ msg: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
    await client.query(
      'INSERT INTO users (name, unit_number, email, password, role) VALUES ($1, $2, $3, $4, $5)',
      [name, unitNumber || null, email, hashedPassword, role]
    );

    // Log admin action
    await client.query('INSERT INTO admin_logs (admin_id, action, details) VALUES ($1, $2, $3)', [
      req.user.id,
      'CREATE_USER',
      `Created user with email ${email}`
    ]);

    res.status(201).json({ msg: 'User created successfully' });
  } catch (err) {
    console.error('Error creating user:', err);
    if (err.code === '23505') {
      res.status(409).json({ msg: 'Email already exists' });
    } else {
      res.status(500).json({ msg: 'Failed to create user' });
    }
  }
});

// Update a user (admin only)
app.put('/api/admin/users/:id', authenticateToken, restrictTo('admin'), async (req, res) => {
  const { id } = req.params;
  const { name, email, unitNumber, role } = req.body;

  if (!name || !email || !role) {
    return res.status(400).json({ msg: 'Name, email, and role are required' });
  }

  try {
    const result = await client.query(
      'UPDATE users SET name = $1, email = $2, unit_number = $3, role = $4 WHERE id = $5 RETURNING *',
      [name, email, unitNumber || null, role, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ msg: 'User not found' });
    }

    // Log admin action
    await client.query('INSERT INTO admin_logs (admin_id, action, details) VALUES ($1, $2, $3)', [
      req.user.id,
      'UPDATE_USER',
      `Updated user with ID ${id}`
    ]);

    res.json({ msg: 'User updated successfully' });
  } catch (err) {
    console.error('Error updating user:', err);
    if (err.code === '23505') {
      res.status(409).json({ msg: 'Email already exists' });
    } else {
      res.status(500).json({ msg: 'Failed to update user' });
    }
  }
});

// Delete a parcel (admin only)
app.delete('/api/admin/parcels/:awbNumber', authenticateToken, restrictTo('admin'), async (req, res) => {
  const { awbNumber } = req.params;
  try {
    const result = await client.query('DELETE FROM parcels WHERE awb_number = $1 RETURNING *', [awbNumber]);
    if (result.rows.length === 0) {
      return res.status(404).json({ msg: 'Parcel not found' });
    }
    // Log admin action
    await client.query('INSERT INTO admin_logs (admin_id, action, details) VALUES ($1, $2, $3)', [
      req.user.id,
      'DELETE_PARCEL',
      `Deleted parcel with AWB ${awbNumber}`
    ]);
    res.json({ msg: 'Parcel deleted' });
  } catch (err) {
    console.error('Error deleting parcel:', err);
    res.status(500).json({ msg: 'Failed to delete parcel' });
  }
});

// **Retrieve Parcels API (Admins see all, Guards see all, Residents see their own uncollected)**
app.get('/api/parcels', authenticateToken, async (req, res) => {
  console.log("🟢 Fetching Parcels for User ID:", req.user.id);

  const user = req.user;
  try {
    let result;
    if (user.role === 'admin' || user.role === 'guard') {
      result = await client.query('SELECT * FROM parcels'); // Admins and guards see all parcels
    } else {
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

// **Log New Parcel API (Guards and Admins Only)**
app.post('/api/parcels', authenticateToken, restrictTo('guard', 'admin'), async (req, res) => {
  const { awbNumber, recipientName, recipientUnit } = req.body;

  if (!awbNumber || !recipientName || !recipientUnit) {
    return res.status(400).json({ msg: 'AWB number, recipient name, and unit are required' });
  }

  try {
    const checkResult = await client.query('SELECT * FROM parcels WHERE awb_number = $1', [awbNumber]);
    if (checkResult.rows.length > 0) {
      return res.status(409).json({ msg: 'Error: This AWB number is already logged.' });
    }

    const result = await client.query(
      'INSERT INTO parcels (awb_number, recipient_name, recipient_unit, delivered_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) RETURNING *',
      [awbNumber, recipientName, recipientUnit]
    );

    // Log admin/guard action
    await client.query('INSERT INTO admin_logs (admin_id, action, details) VALUES ($1, $2, $3)', [
      req.user.id,
      'LOG_PARCEL',
      `Logged parcel with AWB ${awbNumber}`
    ]);

    res.json({ msg: 'Parcel logged successfully', parcel: result.rows[0] });
  } catch (err) {
    console.error('Error logging parcel:', err);
    res.status(500).json({ msg: 'Failed to log parcel. Please try again.' });
  }
});

// **Collect Parcel API (Residents Only)**
app.post('/api/parcels/collect', authenticateToken, restrictTo('resident'), async (req, res) => {
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

// **Temporary Endpoint to Hash a Password (Remove After Use)**
app.post('/api/hash-password', async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ msg: 'Password is required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    res.json({ hashedPassword });
  } catch (err) {
    console.error('Error hashing password:', err);
    res.status(500).json({ msg: 'Failed to hash password' });
  }
});

// **Start Server**
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
