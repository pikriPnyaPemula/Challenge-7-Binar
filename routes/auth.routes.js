const router = require('express').Router();
const {register, login, whoAmI, forgetPassword, resetPassword} = require('../controllers/auth.controllers');
const {restrict} = require('../middlewares/auth.middlewares');

router.post('/register', register);
router.post('/login', login);
router.get('/whoami', restrict, whoAmI);

// render halaman aktivasi
// router.get('/email-activation', (req, res) => {
//     let { token } = req.query;
//     res.render('email-activation', { token });
// });

//update user is_verified true
// router.post('/email-activation', forgetPassword);

// Forget Password
router.get('/reset-password', resetPassword);
router.post('/forget-password', forgetPassword);

module.exports = router;