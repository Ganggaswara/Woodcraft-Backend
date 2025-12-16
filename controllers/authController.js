const { getPool } = require('../config/mysql');
const { User, syncModels } = require('../models');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? undefined : 'please-change-this-secret');
if (!JWT_SECRET) { throw new Error('JWT_SECRET not configured'); }

async function ensureUsersTable() {
  await syncModels();
}

exports.register = async function register(req, res, next) {
  try {
    const { firstName, lastName, name, email, password } = req.body;
    const fullName = name || `${firstName || ''} ${lastName || ''}`.trim() || 'Anonymous';
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    await ensureUsersTable();
    const existing = await User.findOne({ where: { email }, attributes: ['id'] });
    if (existing) {
      return res.status(409).json({ message: 'Email already in use' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const created = await User.create({ name: fullName, email, password: hashed });
    const token = jwt.sign({ id: created.id, email, name: fullName }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(201).json({ token, user: { id: created.id, name: fullName, email } });
  } catch (err) {
    next(err);
  }
};

exports.login = async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });
    await ensureUsersTable();
    const user = await User.findOne({ where: { email }, attributes: ['id', 'name', 'email', 'password'] });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid email or password' });
    const token = jwt.sign({ id: user.id, email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    next(err);
  }
};

