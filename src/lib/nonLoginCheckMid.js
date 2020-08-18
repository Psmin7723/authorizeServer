// 로그인이 필요한 api 마다 해당 미들웨어 실행하여 로그인 검사
const createError = require("http-errors");
const nonLoginCheck = (req, res, next) => {
  const check = res.locals.user;
  if (!check) {
    const code = 401;
    const message = "비로그인 접속 시도";
    next(createError(code, message));
    const filename = __dirname + "/../views/main/index.pug";
    return res.render(filename, { code });
  }
  return next();
};

module.exports = nonLoginCheck;
