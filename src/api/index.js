const api = require('express').Router();
const auth = require('./auth');
const oauth = require('./oauth');

api.use('/', auth);
api.use('/oauth', oauth);

api.get('/', function(req, res, next){
  if(res.locals.user){
    res.redirect('/oauth/regapp');
    return;
  }
  res.render('main');
});

module.exports = api;

 