var express = require('express');
var router = express.Router();
var ctrl = require('../controllers/usersController');
var auth = require('../middlewares/auth');

router.get('/', ctrl.list);
router.get('/me', auth, ctrl.me);
router.get('/:id', ctrl.detail);
router.post('/', auth, ctrl.create);
router.put('/:id', auth, ctrl.update);
router.patch('/:id', auth, ctrl.patch);
router.delete('/:id', auth, ctrl.remove);

module.exports = router;
