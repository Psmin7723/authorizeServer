const Joi = require("joi");
const Member = require("../../models/member");
const authFunctions = require("./auth.functions");
const { createVerifyRule, createLoginToken, createExpiresAt } = authFunctions;

const userRegister = async (regData) => {
  // Joi 파라미터 검증 규칙 생성
  const schema = createVerifyRule("signUp");
  try {
    //Joi 파라미터 검증 실행
    const data = Joi.validate(regData, schema);
    if (data.error) {
      const error = {
        code: 400,
        message: `function userRegister 파라미터 검증 오류:: ${data.error}`,
      };
      return error;
    }
    const { username, password, email, name } = regData;
    // 유저 가입 여부 db 탐색
    const exists = await Member.findByUsername(username);
    if (exists !== null) {
      const error = {
        code: 401,
        message: "이미 존재하는 아이디입니다.",
      };
      return error;
    }
    const member = new Member({
      username,
      email,
      name,
      agree: false,
    });
    // 랜덤 수 생성
    const clientRandom = Math.random().toString();
    // clientId 생성 및 db 저장
    await member.setClientId(clientRandom);
    // clientSecret 생성 및 db 저장
    await member.setClientSecret(clientRandom);
    // chatApiKey 생성 및 db 저장
    await member.setChatApiKey(clientRandom);
    // password 생성 및 db 저장
    await member.setPassword(password);
    // username에 index 생성하고 유일 속성 적용
    await member.collection.createIndex({ username: 1 }, { unique: true });
    // db 저장
    await member.save();
    return true;
  } catch (e) {
    const error = {
      code: 500,
      message: `function userRegister 에러:: ${e}`,
    };
    return error;
  }
};

const userLogin = async (user) => {
  const { username, password } = user;
  // 파라미터 검증 규칙
  const schema = createVerifyRule("signIn");
  // 파라미터 검증
  const data = Joi.validate(user, schema);
  if (data.error) {
    const error = {
      code: 400,
      message: `function userLogin 파라미터 검증 오류:: ${data.error}`,
    };
    return error;
  }

  try {
    const member = await Member.findByUsername(username);
    // db에서 가입여부 확인
    if (member === null) {
      const error = {
        code: 401,
        message: "등록되지 않은 계정입니다.",
      };
      return error;
    }
    // db에서 비밀번호 일치 여부 확인
    const valid = await member.checkPassword(password);
    if (!valid) {
      const error = {
        code: 401,
        message: "아이디 또는 비밀번호가 일치하지 않습니다.",
      };
      return error;
    }
    // 로그인 토큰 생성
    const minutes = 60; // 1시간
    const token = createLoginToken({
      id: member._id,
      username: member.username,
      expiresIn: createExpiresAt(minutes),
    });
    return token;
  } catch (e) {
    const error = {
      code: 500,
      message: `function userLogin 에러:: ${e}`,
    };
    return error;
  }
};

module.exports = {
  userRegister,
  userLogin,
};
