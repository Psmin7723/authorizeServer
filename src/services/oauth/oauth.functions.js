const Joi = require("joi");
const jwt = require("jsonwebtoken");
const xss = require("xss");
const bcrypt = require("bcrypt");

const createVerifyRule = (state) => {
  if (state === "regappPost") {
    const schema = Joi.object().keys({
      clientId: Joi.string().required(),
      clientSecret: Joi.string().required(),
      chatApiKey: Joi.string().required(),
      homepageAddr: Joi.string().required(),
      redirectUris: Joi.string().required(),
      appName: Joi.string(),
      chkReqInfo: Joi.object({
        아이디: Joi.string(),
        이메일: Joi.string(),
        이름: Joi.string(),
      }),
    });
    return schema;
  } else if (state === "authorizeGet") {
    const schema = Joi.object().keys({
      clientId: Joi.string().required(),
      redirectUris: Joi.string().required(),
      state: Joi.string(),
    });
    return schema;
  } else if (state === "authorizePost") {
    const schema = Joi.object().keys({
      clientId: Joi.string().required(),
      redirectUris: Joi.string().required(),
      state: Joi.string(),
      referer: Joi.string().required(),
      username: Joi.string().required(),
      password: Joi.string().required(),
    });
    return schema;
  } else if (state === "callbackPost") {
    const schema = Joi.object().keys({
      clientId: Joi.string().required(),
      redirectUris: Joi.string().required(),
      state: Joi.string(),
      username: Joi.string().required(),
    });
    return schema;
  } else if (state === "tokenPost") {
    const schema = Joi.object().keys({
      client_id: Joi.string().required(),
      redirect_uri: Joi.string(),
      clientSecret: Joi.string().required(),
      grant_type: Joi.string().required(),
      code: Joi.string().required(),
      refreshToken: Joi.string(),
    });
    return schema;
  }
};

const referrerCheck = (referer, hpAddr) => {
  // 홈페이지 주소 '/'제거.
  const refererLastStr = referer.charAt(referer.length - 1);
  const hpAddrLastStr = hpAddr.charAt(hpAddr.length - 1);

  if (refererLastStr == "/") {
    referer = referer.slice(0, -1);
  }
  if (hpAddrLastStr == "/") {
    hpAddr = hpAddr.slice(0, -1);
  }
  if (referer != hpAddr) {
    return false;
  } else {
    return true;
  }
};

const xssCheck = (referer, originUri) => {
  // originUri값이 있을 경우만
  if (originUri !== undefined) {
    // 전체 uri 구하기
    referer = referer + originUri;
  }

  // script uri escape
  const refererCheck = xss(referer);

  // xss 검사
  if (referer != refererCheck) {
    return false;
  }
  return true;
};

const redirectCheck = (redirectUri, redirect_uri) => {
  //등록된 uri와 query로 넘어몬 uri를 비교 검증한다.
  if (redirectUri != redirect_uri) {
    return false;
  }
  return true;
};

const createCode = async (data) => {
  const hash = await bcrypt.hash(data, 10);
  return hash;
};

const createRedirect = (uri, code, state) => {
  const result = `${uri}?code=${code}&state=${state}`;

  return result;
};

const createExpiresAt = (type, time) => {
  if (type === "minute") {
    const expiresAt = Date.now() + 3600000 * 9 + 60 * time * 1000;
    return expiresAt;
  } else if (type === "hour") {
    const expiresAt = Date.now() + 3600000 * 9 + 60 * time * 60000;
    return expiresAt;
  } else if (type === "day") {
    const expiresAt = Date.now() + 3600000 * 9 + 60 * time * 60000 * 24;
    return expiresAt;
  } else {
    time = "TypeError";
    return time;
  }
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

// 로그인 토큰 생성 함수
const createAccessToken = ({ id, secret, user, expiresIn }) => {
  const token = jwt.sign(
    {
      id,
      secret,
      user,
    },
    process.env.OAUTH_JWT_ACCESS_SECRET_KEY,
    {
      expiresIn,
    }
  );
  return token;
};

// 로그인 토큰 생성 함수
const createRefreshToken = ({ id, secret, user, expiresIn }) => {
  const token = jwt.sign(
    {
      id,
      secret,
      user,
    },
    process.env.OAUTH_JWT_REFRESH_SECRET_KEY,
    {
      expiresIn,
    }
  );
  return token;
};

const jwtVerify = async (type, token) => {
  let key = "";
  if (type === "access_token") {
    key = process.env.OAUTH_JWT_ACCESS_SECRET_KEY;
  } else if (type === "refresh_token") {
    key = process.env.OAUTH_JWT_REFRESH_SECRET_KEY;
  }
  const data = jwt.verify(token, key, async (err, decoded) => {
    if (err) {
      return false;
    }
    return decoded;
  });
  return data;
};

const expiresTimeComparison = async (expiresAt) => {
  const now = Date.now() + 3600000 * 9;
  if (expiresAt < now) {
    return false;
  }
  return true;
};

const serialize = (body) => {
  delete body.clientSecret;
  delete body.password;
  delete body.code;
  return body;
};

module.exports = {
  createVerifyRule,
  referrerCheck,
  xssCheck,
  redirectCheck,
  createCode,
  createRedirect,
  createExpiresAt,
  createLoginToken,
  expiresTimeComparison,
  createAccessToken,
  createRefreshToken,
  jwtVerify,
  serialize,
};
