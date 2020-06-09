const express = require("express");

const app = require("./config/express")(express);

const path = require("path");
const api = require("./api");

const jwtMiddleware = require('./lib/jwtMiddleware');
app.set('views',__dirname + '/views');
app.set('view engine', 'pug');
app.use(express.static(path.join(__dirname, "/")));

app.use(jwtMiddleware); // 검증 미들웨어가 먼저 사용되어야 함.
app.use(api);

const port = process.env.PORT || 8080;
app.listen(port, ()=> {
  console.log(`Connected, `+port+` port!`);
})


