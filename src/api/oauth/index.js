const oauth = require('express').Router();
const oauthCtrl = require('../../services/oauth/oauth.ctrl');
const logChkMiddleware = require('../../lib/loginCheckMiddleware');
const reateLimit = require('express-rate-limit');
const limiter = reateLimit({
  windowMs: 1 * 60 * 1000, // 1분
  max: 20, // 각각의 IP를 20개의 request로 제한
  headers: true,
  message:"해당 IP의 요청이 너무 많습니다. 잠시 후에 다시 시도하십시오",
})

oauth.get('/regapp',logChkMiddleware,oauthCtrl.regAppView);
oauth.post('/regapp',logChkMiddleware,oauthCtrl.regApp);

oauth.get('/authorize',limiter,oauthCtrl.authLoginView);
oauth.post('/authorize',oauthCtrl.authLogin);


oauth.post('/callback',logChkMiddleware,oauthCtrl.callback);
oauth.post('/token',oauthCtrl.token);


module.exports = oauth;