import express, { json } from 'express';
import { connect, Types } from 'mongoose';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import Company from './models/company.js';
import User from './models/user.js';

dotenv.config();

const app = express();

// --- Middleware ---
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(json());
app.use(morgan('dev'));

// --- DB Connection ---
connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// --- Auth Middleware ---
const authMiddleware = (roles = []) => async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: 'Token required' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (roles.length && !roles.includes(decoded.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification failed:', err);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// --- Routes ---

// Register Company
app.post('/api/company/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const normalizedEmail = email.toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 10);
    const company = new Company({ name, email: normalizedEmail, password: hashedPassword });
    await company.save();
    res.json({ message: 'Company registered' });
  } catch (err) {
    console.error('Company registration error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Company Login
app.post('/api/company/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = email.toLowerCase();

    const company = await Company.findOne({ email: normalizedEmail });
    if (!company) {
      console.log('Login failed: Company not found');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = bcrypt.compare(password, company.password);
    console.log('Password match:', isMatch);
    if (!isMatch) {
      console.log('Login failed: Incorrect password');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: company._id, role: 'company' }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    console.error('Company login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Register User
app.post('/api/user/register', async (req, res) => {
  try {
    const { name, email, password, companyId } = req.body;
    const normalizedEmail = email.toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email: normalizedEmail,
      password: hashedPassword,
      companyId,
    });
    await user.save();
    res.json({ message: 'User registered' });
  } catch (err) {
    console.error('User registration error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// User Login
app.post('/api/user/login', async (req, res) => {
  try {
    const { email, password, companyId } = req.body;
    const normalizedEmail = email.toLowerCase();

    console.log('Login attempt:', { email: normalizedEmail, companyId, password});

    const user = await User.findOne({
      email: normalizedEmail,
      companyId: new Types.ObjectId(companyId),
    });

    if (!user) {
      console.log('Login failed: User not found');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = bcrypt.compare(password, user.password);
    console.log('Password match:', isMatch);
    if (!isMatch) {
      console.log('Login failed: Incorrect password');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, companyId, role: 'user' },
      process.env.JWT_SECRET
    );
    res.json({ token });
  } catch (err) {
    console.error('User login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Companies
app.get('/api/companies', async (req, res) => {
  try {
    const companies = await Company.find({}, 'name');
    res.json(companies);
  } catch (err) {
    console.error('Fetching companies error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected Route
app.get('/api/home', authMiddleware(['user', 'company']), (req, res) => {
  res.json({ message: 'Create your newspaper' });
});

// --- Server Start ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
