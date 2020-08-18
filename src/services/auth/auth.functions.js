const Joi = require("joi");
const jwt = require("jsonwebtoken");

// 파라매터 검증 규칙 제정 함수
const createVerifyRule = (state) => {
  if (state === "signUp") {
    const schema = Joi.object().keys({
      username: Joi.string().alphanum().min(3).max(20).required(),
      password: Joi.string().required(),
      name: Joi.string(),
      email: Joi.string().email({ minDomainSegments: 2 }).required(),
    });
    return schema;
  } else if (state == "signIn") {
    const schema = Joi.object().keys({
      username: Joi.string().alphanum().min(3).max(20).required(),
      password: Joi.string().required(),
    });
    return schema;
  }
};
const createExpiresAt = (minute) => {
  minute = minute * 1000;
  const expiresAt = Date.now() + 3600000 * 9 + 60 * minute;
  return expiresAt;
};

// 로그인 토큰 생성 함수
const createLoginToken = ({ id, username, expiresIn }) => {
  const token = jwt.sign(
    {
      _id: id,
      username: username,
    },
    process.env.JWT_SECRET_KEY,
    {
      expiresIn: expiresIn,
    }
  );
  return token;
};

const serialize = (body) => {
  delete body.password;
  return body;
};



module.exports = {
  serialize,
  createVerifyRule,
  createLoginToken,
  createExpiresAt,
};
