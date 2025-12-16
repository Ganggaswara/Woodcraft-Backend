require('dotenv').config();
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var helmet = require('helmet');
var cors = require('cors');
var compression = require('compression');
var rateLimit = require('express-rate-limit');
var productsRouter = require('./routes/products');
var usersRouter = require('./routes/users');
var authRouter = require('./routes/auth');
var transactionsRouter = require('./routes/transactions');
var app = express();
var db = require('./config/mysql');
var models = require('./models');

db.getPool();
models.syncModels().catch(function(_){});

app.use(helmet());
app.use(compression());
var allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map(function(s){ return s.trim(); }).filter(Boolean);
var originOption = allowedOrigins.indexOf('*') >= 0 ? '*' : function(origin, callback){
  if (!origin) return callback(null, true);
  var ok = allowedOrigins.some(function(a){
    if (a === origin) return true;
    try {
      var u = new URL(origin);
      var b = new URL(a);
      if (u.hostname === b.hostname && u.protocol === b.protocol) {
        if (b.port) return u.port === b.port;
        return true;
      }
      return false;
    } catch(_) {
      return a === origin;
    }
  });
  callback(null, ok);
};
app.use(cors({ origin: originOption }));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // Maksimal 100 request per IP dalam 15 menit
    message: 'Too many requests from this IP, please try again later.',
});

app.use(limiter);

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get('/health', function(req, res) { res.json({ status: 'ok' }); });
app.use('/api/v1/products', productsRouter);
app.use('/api/v1/users', usersRouter);
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/transactions', transactionsRouter);

var notFound = require('./middlewares/notFound');
var errorHandler = require('./middlewares/errorHandler');

app.use(notFound);

app.use(errorHandler);

module.exports = app;
