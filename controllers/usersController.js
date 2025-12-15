const { User } = require('../models');
const bcrypt = require('bcryptjs');

exports.list = async function list(req, res, next) {
  try {
    const rows = await User.findAll({ attributes: ['id', 'name', 'email', 'role'], limit: 50, order: [['id', 'ASC']] });
    return res.json({ users: rows });
  } catch (err) {
    next(err);
  }
};

exports.me = async function me(req, res, next) {
  try {
    const userId = req.user && req.user.id;
    if (!userId) return res.status(401).json({ message: 'Not authenticated' });
    const user = await User.findOne({ where: { id: userId }, attributes: ['id', 'name', 'email', 'role'] });
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ user });
  } catch (err) {
    next(err);
  }
};

exports.detail = async function detail(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: 'invalid id' });
    const user = await User.findOne({ where: { id }, attributes: ['id', 'name', 'email', 'role'] });
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ user });
  } catch (err) {
    next(err);
  }
};

exports.create = async function create(req, res, next) {
  try {
    const { name, email, password, role = 'customer' } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ message: 'name, email, password are required' });
    const exists = await User.findOne({ where: { email }, attributes: ['id'] });
    if (exists) return res.status(409).json({ message: 'Email already in use' });
    const hashed = await bcrypt.hash(password, 10);
    const created = await User.create({ name, email, password: hashed, role });
    return res.status(201).json({ id: created.id });
  } catch (err) {
    next(err);
  }
};

exports.update = async function update(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: 'invalid id' });
    const user = await User.findOne({ where: { id } });
    if (!user) return res.status(404).json({ message: 'User not found' });
    const { name, email, role, password } = req.body || {};
    const payload = {};
    if (name != null) payload.name = name;
    if (email != null) {
      const exists = await User.findOne({ where: { email }, attributes: ['id'] });
      if (exists && exists.id !== id) return res.status(409).json({ message: 'Email already in use' });
      payload.email = email;
    }
    if (role != null) payload.role = role;
    if (password != null) payload.password = await bcrypt.hash(password, 10);
    await User.update(payload, { where: { id } });
    const updated = await User.findOne({ where: { id }, attributes: ['id', 'name', 'email', 'role'] });
    return res.json({ user: updated });
  } catch (err) {
    next(err);
  }
};

exports.patch = async function patch(req, res, next) {
  return exports.update(req, res, next);
};

exports.remove = async function remove(req, res, next) {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ message: 'invalid id' });
    const user = await User.findOne({ where: { id }, attributes: ['id'] });
    if (!user) return res.status(404).json({ message: 'User not found' });
    await User.destroy({ where: { id } });
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};
