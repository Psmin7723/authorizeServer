const auth = require("express").Router();
const authCtrl = require("../../services/auth/auth.ctrl");
const createError = require("http-errors");
const authFunctions = require("../../services/auth/auth.functions");
const { serialize } = authFunctions;
const { userRegister, userLogin } = authCtrl;

//등록 페이지
auth.get("/register", (req, res) => {
  // 로그인 중인 경우
  if (res.locals.user) {
    return res.redirect("/oauth/regapp");
  }
  return res.render("auth/register");
});

// 등록 처리
auth.post("/register", async (req, res, next) => {
  const regData = req.body;
  try {
    // 유저 회원가입 진행 함수 실행
    const regResult = await userRegister(regData);
    const { code, message } = regResult;
    // 민감한 정보 삭제
    req.body = serialize(regData);
    // 서버 오류
    if (code >= 500) {
      // 로그기록
      next(createError(code, message));
      return res.render("main/error", { code });
      // 클라이언트 오류
    } else if (code >= 400 && code < 500) {
      return res.send({ code, message });
    }
    // 로그인 페이지 이동
    return res.send({ redirect: "/login" });
  } catch (e) {
    const code = 500;
    const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
    req.body = serialize(regData);
    next(createError(code, message));
    return res.render("main/error", { code });
  }
});

// 로그인 페이지
auth.get("/login", (req, res) => {
  if (res.locals.user) {
    return res.redirect("/oauth/regapp");
  }
  return res.render("auth/login");
});

// 로그인 처리
auth.post("/login", async (req, res, next) => {
  const user = req.body;
  try {
    const loginResult = await userLogin(user);
    const { code, message } = loginResult;
    req.body = serialize(user);
    if (code >= 500) {
      // 로그 기록을 위한 에러발생
      next(createError(code, message));
      return res.render("main/error", { code });
    } else if (code >= 400 && code < 500) {
      return res.send({ code, message });
    }

    // 로그인 성공 cookie에 token 세팅
    res.cookie("access_token", loginResult, {
      maxAge: 1000 * 60 * 60 * 24 * 3,
      httpOnly: true,
    });
    return res.send({ redirect: "/oauth/regapp" });
  } catch (e) {
    req.body = serialize(user);
    const code = 500;
    const message = `api :: ${req.method} ${req.path}, 에러:: ${e}`;
    next(createError(code, message));
    return res.render("main/error", { code });
  }
});

// 로그아웃 처리
auth.post("/logout", (req, res) => {
  res.cookie("access_token");
  res.status = 204;
  res.redirect("/");
});

module.exports = auth;
