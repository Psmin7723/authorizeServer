const Oauth = require("../models/oauth");
const createError = require("http-errors");
const {
  referrerCheck,
  xssCheck,
  redirectCheck,
} = require("../services/oauth/oauth.functions");

// 각종 검증 로직 미들웨어
const verifyCheck = async (req, res, next) => {
  let client_id, redirect_uri, manager;
  if (Object.keys(req.query).length === 0) {
    client_id = req.body.client_id;
    redirect_uri = req.body.redirect_uri;
    manager = req.body.manager;
  } else {
    client_id = req.query.client_id;
    redirect_uri = req.query.redirect_uri;
    manager = req.query.manager;
  }

  const referer = req.headers.referer;
  const originUri = req.originalUrl;
  let code = null;
  let message = null;
  try {
    //query와 등록자 대조
    const oauth = await Oauth.findByClientId(client_id);
    if (!oauth) {
      code = 412;
      message = `function verifyCheck 파라미터 검증 오류:: 미등록 client_id `;
      next(createError(code, message));
      message = `등록된 client_id가 아닙니다.`;
      return res.send({ code, message });
    }
    if (!manager) {
      //referer 검증
      const hpAddr = oauth.client.homepageAddr;
      const refResult = referrerCheck(referer, hpAddr);

      if (!refResult) {
        code = 412;
        message = `function verifyCheck 파라미터 검증 오류:: referrer 불일치 `;
        next(createError(code, message));
        message = `신청한 Homepage Address와 referrer 주소가 일치하지 않습니다.`;
        return res.send({ code, message });
      }
    }

    //xss uri 검증
    const xssResult = xssCheck(referer, originUri);
    if (!xssResult) {
      code = 412;
      message = `function verifyCheck 파라미터 검증 오류:: xss 탐지 `;
      next(createError(code, message));
      message = `script를 사용하실 수 없습니다.`;
      return res.send({ code, message });
    }

    //redirect 대조 검증
    const redirectUri = oauth.client.redirectUris;
    const redirResult = redirectCheck(redirectUri, redirect_uri);
    if (!redirResult) {
      code = 412;
      message = `function verifyCheck 파라미터 검증 오류:: redirectUri 불일치 `;
      next(createError(code, message));
      message = `등록한 callback URL과 보내온 redirect_uri 파라미터가 일치하지 않습니다.`;
      return res.send({ code, message });
    }
  } catch (e) {
    code = 500;
    message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
    next(createError(code, message));
    return res.render("main/error", { code });
  }
  return next();
};

module.exports = verifyCheck;
