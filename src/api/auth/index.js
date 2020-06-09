const auth = require('express').Router();
const authCtrl = require('../../services/auth/auth.ctrl');

auth.get('/register',authCtrl.registerView);
auth.post('/register',authCtrl.userRegister);

auth.get('/login',authCtrl.loginView);
auth.post('/login',authCtrl.userLogin);

auth.post('/logout', authCtrl.userLogout);

module.exports = auth;
