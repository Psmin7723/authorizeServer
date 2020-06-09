const loginCheck = (req, res, next) => {
  const check = res.locals.user;
  if(!check) {
    res.status(401).send(`로그인이 필요합니다.`)
    return;
  }
  
  return next();
};

module.exports = loginCheck;

