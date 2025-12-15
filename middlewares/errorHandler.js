module.exports = function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  const payload = {
    message: err.message || 'Internal Server Error',
    status,
  };
  if (req.app.get('env') === 'development' && err.stack) {
    payload.stack = err.stack;
  }
  res.status(status).json(payload);
};

