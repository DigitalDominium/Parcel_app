require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json()); // To parse JSON bodies
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

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

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('MongoDB error:', err));

// Load routes
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// Protect parcel routes with authentication
app.use('/api/parcels', authenticateToken, authRoutes);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});