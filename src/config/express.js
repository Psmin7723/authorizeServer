module.exports = function(express){
  require('dotenv').config();
  const session = require('express-session');
  const MongoosStore = require('connect-mongo')(session);
  const cookieParser = require('cookie-parser');
  const {SESSION_KEY, DATABASE_SESSION_URI} = process.env;
  const cors = require('cors');
  
  const helmet = require('helmet');

  const app = express();
  
  app.disable("x-powered-by");
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(cookieParser());
  app.use(helmet());
  app.use(helmet.xssFilter())
  app.use(cors());
  
  const  expiryDate = new Date((Date.now() + 3600000 * 9) + 60 * 60 * 1000) // 1 hour

  app.use(session({
    secret: SESSION_KEY,
    resave: false,
    name: 'sessionId',
    cookie: {
      secure: true, //https를 통해서만 쿠키전송
      httpOnly: true, // javascript가 아닌 https를 통해서만 전송, xss공격 보호
      expires: expiryDate
    },
    saveUninitialized: true,
    store: new MongoosStore({
      url: DATABASE_SESSION_URI,
      collection: "sessions"
    })
  }));

  return app;
};