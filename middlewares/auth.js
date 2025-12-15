const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'please-change-this-secret';

module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || req.headers['x-access-token'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });
  const token = authHeader.replace(/^Bearer\s+/i, '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // contains id, email, name
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};
