const Member = require("../models/member");
const { agreeProcessLogic } = require("../services/oauth/oauth.ctrl");

// 이미 로그인한 유저의 정보제공 동의 여부에 따른 처리 미들웨어
const oauthLoginCheck = async (req, res, next) => {
  const user = res.locals.user;
  if (user) {
    try {
      const member = await Member.findByUsername(user.username);
      const { client_id, redirect_uri, state } = req.query;
      if (member.agree === true) {
        const agreeResult = await agreeProcessLogic(
          client_id,
          redirect_uri,
          state,
          user.username
        );
        const { code, message, clientMessage } = agreeResult;
        if (code >= 500) {
          next(createError(code, message));
          return res.render("main/error", { code });
        } else if (code >= 400 && code < 500) {
          next(createError(code, message));
          return res.send({ code, message: clientMessage });
        }
        return res.redirect(agreeResult);
      }
      return next();
    } catch (e) {
      code = 500;
      message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
      next(createError(code, message));
      return res.render("main/error", { code });
    }
  }
  return next();
};

module.exports = oauthLoginCheck;
