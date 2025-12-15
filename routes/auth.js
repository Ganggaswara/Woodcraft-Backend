var express = require('express');
var ctrl = require('../controllers/authController');

var router = express.Router();

router.post('/signup', ctrl.register);
router.post('/login', ctrl.login);

module.exports = router;
