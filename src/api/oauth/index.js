const oauth = require("express").Router();
const createError = require("http-errors");
const nonLoginCheck = require("../../lib/nonLoginCheckMid");
const verifyCheck = require("../../lib/verifyCheckMid");
const oauthLoginCheck = require("../../lib/oauthLoginCheckMid");
const oauthFunctions = require("../../services/oauth/oauth.functions");
const { serialize } = oauthFunctions;
const oauthCtrl = require("../../services/oauth/oauth.ctrl");
const {
  regAppView,
  regApp,
  authLoginView,
  authLogin,
  callback,
  loadAgreeList,
  token,
  agreeProcessLogic,
} = oauthCtrl;

// app 등록 페이지 뷰
oauth.get("/regapp", nonLoginCheck, async (req, res, next) => {
  try {
    const user = res.locals.user;
    const appViewResult = await regAppView(user);
    const { code, message } = appViewResult;
    if (code >= 500) {
      next(createError(code, message));
      return res.render("main/error", { code });
    }
    return res.render("oauth/register", { client: appViewResult });
  } catch (e) {
    const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
    const code = 500;
    next(createError(code, message));
    return res.render("main/error", { code });
  }
});

// app 등록 처리
oauth.post("/regapp", nonLoginCheck, async (req, res, next) => {
  try {
    const regData = req.body;
    const user = res.locals.user;
    //app 등록시 받아온 body와 로그인 중인 유저 정보를 인자로 전달
    const regAppResult = await regApp(regData, user);
    req.body = serialize(regData);
    const { code, message } = regAppResult;
    // 각종 에러 알림
    if (code >= 500) {
      // 로그기록
      next(createError(code, message));
      return res.render("main/error", { code });
    } else if (code >= 400 && code < 500) {
      next(createError(code, message));
      return res.send({ code, message });
    }
    // 정상처리
    return res.send({ message: regAppResult });
  } catch (e) {
    const code = 500;
    const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
    next(createError(code, message));
    return res.render("main/error", { code });
  }
});

oauth.get(
  "/agreement",
  verifyCheck,
  oauthLoginCheck,
  async (req, res, next) => {
    try {
      const { client_id, redirect_uri, state } = req.query;
      //비동의인 경우 동의 페이지 리스트 가져오기
      const agreeList = await loadAgreeList(client_id);
      // 동의 페이지 랜더링
      res.render("oauth/agreement", {
        client_id,
        redirect_uri,
        state,
        reqInfo: agreeList,
      });
    } catch (e) {
      const code = 500;
      const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
      next(createError(code, message));
      return res.render("main/error", { code });
    }
  }
);

// 최초 Owner 접속, Owner는 로그인 또는 비로그인으로 접속
oauth.get(
  "/authorize",
  verifyCheck,
  oauthLoginCheck,
  async (req, res, next) => {
    const { client_id, redirect_uri, state } = req.query;
    const user = res.locals.user;
    // 비로그인시 로그인 페이지 랜더링
    if (!user) {
      return res.render("oauth/login", {
        client_id,
        redirect_uri,
        state,
      });
    }
    try {
      //로그인 중일 시 동의 페이지 리스트 가져오기
      const loginResult = await authLoginView(client_id, redirect_uri, state);
      // 각종 에러 알림
      const { code, message, clientMessage } = loginResult;
      // 각종 에러 알림
      if (code >= 400 && code < 500) {
        // 로그기록
        next(createError(code, message));
        return res.send({ code, message: clientMessage });
      }
      // 동의 페이지 랜더링
      return res.render("oauth/agreement", {
        client_id,
        redirect_uri,
        state,
        reqInfo: loginResult,
      });
    } catch (e) {
      const code = 500;
      const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
      next(createError(code, message));
      return res.render("main/error", { code });
    }
  }
);
// oauth서버 로그인 처리
oauth.post("/authorize", async (req, res, next) => {
  try {
    const referer = req.headers.referer;
    const bodyData = req.body;
    // 로그인 수행
    const loginResult = await authLogin(bodyData, referer);
    req.body = serialize(bodyData);
    const { code, message, clientMessage } = loginResult;
    if (code >= 500) {
      next(createError(code, message));
      return res.render("main/error", { code });
    } else if (code >= 412 && code < 500) {
      next(createError(message, code));
      return res.send({ code, message: clientMessage });
    } else if (code === 401) {
      return res.send({ code, message });
    }

    // 로그인 성공 cookie에 token 세팅
    res.cookie("access_token", loginResult.token, {
      maxAge: 1000 * 60 * 60 * 24 * 3,
      httpOnly: true,
    });
    const { client_id, redirect_uri, state } = req.body;
    const redirect = `/oauth/agreement?client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}&manager=${true}`;
    return res.send({ redirect });
  } catch (e) {
    const code = 500;
    const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
    req.body = serialize(req.body);
    next(createError(code, message));
    return res.render("main/error", { code });
  }
});
// 동의 후 들어오는 api
oauth.post(
  "/callback",
  verifyCheck,
  oauthLoginCheck,
  async (req, res, next) => {
    try {
      const bodyData = req.body;
      const username = res.locals.user.username;
      // 동의 사실을 db에 업데이트
      const callbackResult = await callback(bodyData, username);
      const { code, message, clientMessage } = callbackResult;
      if (code >= 500) {
        next(createError(code, message));
        return res.render("main/error", { code });
      } else if (code >= 400 && code < 500) {
        next(createError(message, code));
        return res.send({ code, message: clientMessage });
      }
      return res.redirect(callbackResult);
    } catch (e) {
      const code = 500;
      const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
      next(createError(code, message));
      return res.render("main/error", { code });
    }
  }
);

// 접속 토큰 및 재발행 토큰 처리 api
oauth.post("/token", oauthLoginCheck, async (req, res, next) => {
  try {
    const bodyData = req.body;
    // 토큰 생성
    const tokenResult = await token(bodyData);
    req.body = serialize(bodyData);
    const { code, message, clientMessage } = tokenResult;
    if (code >= 500) {
      next(createError(code, message));
      return res.render("main/error", { code });
    } else if (code >= 400 && code < 500) {
      next(createError(message, code));
      return res.send({ code, message: clientMessage });
    }
    // client 서버로 토큰 send
    return res.send({ access_token: tokenResult });
  } catch (e) {
    const code = 500;
    const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
    req.body = serialize(req.body);
    next(createError(code, message));
    return res.render("main/error", { code });
  }
});

module.exports = oauth;
