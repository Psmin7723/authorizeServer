const jwt = require("jsonwebtoken");
const Member = require("../models/member");

// api 접속시 마다 로그인 토큰을 검사 후 만료기간에 따라 토큰 갱신
const jwtMiddleware = async (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) return next();
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    res.locals.user = {
      _id: decoded._id,
      username: decoded.username,
    };
    //UTC 기준 1970년 1월 1일 0시 0분 0초부터 현재까지 경과된 시간의 초 반환
    const now = Math.floor(Date.now() / 1000);
    //토큰 만료 일이 1.5일보다 조금 남는 경우
    if (decoded.exp - now < 60 * 60 * 24 * 1.5) {
      const member = await Member.findById(decoded._id);
      // 토큰 재생성
      const token = member.generateToken();
      res.cookie("access_token", token, {
        maxAge: 1000 * 60 * 60 * 24 * 3,
        httpOnly: true,
      });
    }
    return next();
  } catch (e) {
    return next();
  }
};
module.exports = jwtMiddleware;
