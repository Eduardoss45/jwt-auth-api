// * imports
const express = require('express');
const router = express.Router();
const { checkEmptyBody, checkToken } = require('../middlewares');
const {
  welcomeController,
  registerController,
  loginController,
  userController,
  resendCodeController,
  refreshToken,
  logoutController,
} = require('../controllers');

// * rotas

// * publico
router.get('/', welcomeController);
router.post('/auth/register', checkEmptyBody, registerController);
router.post('/auth/login', checkEmptyBody, loginController);
router.post('/auth/resend-code', checkEmptyBody, resendCodeController);
router.post('/auth/refresh', refreshToken);
router.post('/auth/logout', logoutController);

// * privado
router.get('/user/:id', checkToken, userController);

// * export
module.exports = router;
