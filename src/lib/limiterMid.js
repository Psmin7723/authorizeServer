const rateLimit = require("express-rate-limit");
const time = 1 * 60 * 1000; //1분
const maxConnect = 50; // 각각의 IP를 50개의 request로 제한

// api 접속시 마다 ip의 트래픽을 검사 1분에 50회를 넘을 시 접속 제한(1분)
const limiter = rateLimit({
  windowMs: time,
  max: maxConnect,
  headers: true,
  message: "해당 IP의 요청이 너무 많습니다. 잠시 후에 다시 시도하십시오",
});

module.exports = limiter;
