var express = require('express');
var ctrl = require('../controllers/productsController');
var auth = require('../middlewares/auth');

var router = express.Router();

router.get('/', ctrl.list);
router.get('/:slug', ctrl.detail);
router.post('/', auth, ctrl.create);
router.put('/:id', auth, ctrl.update);
router.delete('/:id', auth, ctrl.remove);
router.patch('/:id', auth, ctrl.patch);

module.exports = router;
