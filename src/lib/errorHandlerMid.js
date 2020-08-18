const createError = require("http-errors");
const moment = require("moment");
const { logger } = require("../configs/winston");

// error handler
const errHandler = (err, req, res, next) => {
  let apiError = err;
  if (!err.status) {
    apiError = createError(err);
  }

  if (process.env.NODE_ENV === "development") {
    const errObj = {
      req: {
        headers: req.headers,
        query: req.query,
        body: req.body,
        route: req.route,
      },
      error: {
        message: apiError.message,
        stack: apiError.stack,
        status: apiError.status,
      },
      user: req.user,
    };

    logger.error(`${moment().format("YYYY-MM-DD HH:mm:ss")}`, errObj);
  } else {
    console.log('여기와?');
    // res.locals.message = apiError.message;
    // res.locals.error = apiError;
  }

  // render the error page
  return next();
};

module.exports = errHandler;
