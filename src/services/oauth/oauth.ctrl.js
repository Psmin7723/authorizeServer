const Member = require('../../models/member');
const Oauth = require('../../models/oauth');
const jwt = require('jsonwebtoken');
const xss = require("xss");

exports.regAppView = async (req, res, next) => {
  try{
    const user = res.locals.user;
    if(!user) {
      res.status(401).send('로그인이 필요합니다.')
      return
    }
    
    const userInfo = await Oauth.findByUsername(user.username);
    if(!userInfo){
      const userInfo = await Member.findByUsername(user.username);
      res.render('oauth/register',{client:userInfo.client});
      return;
    }
    res.render('oauth/register',{client:userInfo.client});
    
  }catch(e){
    console.log(e);
  }
}
exports.regApp = async (req, res, next) => {
  try {

    const { clientId, clientSecret, homepageAddr, redirectUris, appName } = req.body;
    
    const reqInfo = JSON.parse(req.body.chkReqInfo);
    const grants = ['authorization_code', 'refresh_token'];
    const username = res.locals.user.username;

    if(!clientId || !clientSecret || !homepageAddr || !redirectUris || !appName || !reqInfo || !grants) {
      res.send({msg:false, valid:500});
      return;
    }
    let oauth = new Oauth({
      client: { 
        clientId, 
        clientSecret, 
        grants, 
        redirectUris, 
        reqInfo,
        appName,
        homepageAddr,
        username,
      },
    })
    await oauth.save();
    res.send({msg:true});
  }catch(e){
    console.log(e);
  } 
}
/***************** 로그인 화면  *******************/
exports.authLoginView = async (req, res, next) => {
  try {
    const { client_id, redirect_uri, state } = req.query;

    /***************** null, referer, redirect 검증 ******************/
    if(!client_id || !redirect_uri || !state){
      res.status(500).send('필수 쿼리 데이터가 존재하지 않습니다.');
      return;
    } 
    //클라이언트 정보 찾기
    const oauth = await Oauth.findByClientId(client_id);
    // 해당하는 정보가 없을때
    if(!oauth){
      res.status(500).send('client_id에 해당하는 정보가 없습니다.');
      return;
    }
    //클라이언트와 query검증
    const redirectUri = oauth.client.redirectUris;
    let hpAddr = oauth.client.homepageAddr;   
    let referer = req.headers.referer;

    if(!referer){
      res.status(500).send('referrer정보를 받아올 수 없습니다.');
      return;
    }
    
    const hpAddrLastStr = hpAddr.charAt(hpAddr.length-1);
    const refererLastStr = referer.charAt(referer.length-1);
    //////// referer 검증 ///////
    if(refererLastStr == '/'){
      referer = referer.slice(0,-1);
    }
    if(hpAddrLastStr == '/'){
      hpAddr = hpAddr.slice(0,-1);
    }
   
    if(referer != hpAddr) {
      const msg = '접속요청 도메인과 등록 도메인이 일치하지 않습니다.'
      res.redirect(redirectUri+`?accessFailMsg=${msg}&state=${state}`);
      return;
    }
   
    const fullUrl = referer + req.originalUrl;
    const refererCheck = xss(fullUrl);
    
    // xss 대비 referer검사
    if(fullUrl != refererCheck) {
      const msg = 'script로 의심되는 uri가 있습니다.'
      res.redirect(redirectUri+`?accessFailMsg=${msg}&state=${state}`);
      return;
    }

    //등록된 uri와 query로 넘어몬 uri를 비교 검증한다. 
    if(redirectUri != redirect_uri){
      msg = 'callback uri가 일치하지 않습니다.'
      res.redirect(`${redirectUri}?accessFailMsg=${msg}`)
      return;
    }
    
    // 유저가 로그인 되어 있는지 체크
    if(res.locals.user){
      const member = await Member.findByUsername(res.locals.user.username);
      const hide = member.serialize();
      req.body = hide;

      if(member.agree == true) {
        // 이미 동의한 상태라면 code를 생성후 돌려준다. 
        const username = res.locals.user.username;  
        const code = await oauth.setBcrypt(Math.random().toString());
        const expiresAt = (Date.now() + 3600000 * 9) + (60 * 10000) //10분
        await oauth.updateByAuthCode(code,expiresAt,redirect_uri,username);
        
        //여긴 get인데 어떻게 post로 보낼것인지 생각해보자.
        res.redirect(`${redirectUri}?code=${code}&state=${state}`)
        return;
      }else{
        //이미 로그인 하였지만 동의하지 않은 사람
        let reqInfo = oauth.client.reqInfo;
        reqInfo = Object.keys(reqInfo);
      
        res.render('oauth/agreement',{'client_id':client_id,'redirect_uri':redirect_uri,'state':state,'reqInfo':reqInfo});
        return;
      }
    }else {
      res.render('oauth/login',{'client_id':client_id,'redirect_uri':redirect_uri,'state':state});
    }   
  }catch(e){
    console.log(e);
  }
}
/***************** 로그인 진행  *******************/
exports.authLogin = async (req, res, next) => {
  try{
    
    const {client_id, redirect_uri, state, username, password} = req.body;
    
    // xss 대비 referer검사
    const referer = req.headers.referer;
    const refererCheck = xss(referer);
    
    if(referer != refererCheck) {
      const msg = 'script로 의심되는 uri가 있습니다.'
      res.redirect(redirectUri+`?accessFailMsg=${msg}&state=${state}`);
      return;
    }

    if(!username || !password) {
      await res.send({msg:false, valid:500});
      return;
    }
    const member = await Member.findByUsername(username);
  
    if(!member || member == null) {
      await res.send({msg:false, valid:409});
      return;
    }
    
    const valid = await member.checkPassword(password);  
    if (!valid || valid == false) {
      await res.send({msg:false, valid:401});
      return;
    }
    
    // oauth2 서버의 jwt 로그인 토큰 
    const token = await member.generateToken(); 
    const hide = member.serialize();
    req.body = hide;
    await res.cookie('access_token', token,{
      maxAge: 1000 * 60 * 60 * 24 * 3,
      httpOnly: true,
    })
    const oauth = await Oauth.findByClientId(client_id);

    if(!oauth){
      console.log('oauth가 null입니다.');
      return;
    }
    //로그인 하였고 이미 동의한 적이 있는 경우
    if(member.agree == true) {
      // 이미 동의한 상태라면 code를 생성후 돌려준다. 
      const username = member.username;  
      const code = await oauth.setBcrypt(Math.random().toString());
      const expiresAt = (Date.now() + 3600000 * 9) + (60 * 10000) //10분
      await oauth.updateByAuthCode(code,expiresAt,redirect_uri,username);
    
      //여긴 get인데 어떻게 post로 보낼것인지 생각해보자.
      res.redirect(`${redirect_uri}?code=${code}&state=${state}`)
      return;
    }

    let reqInfo = oauth.client.reqInfo;
    reqInfo = Object.keys(reqInfo);
    res.render('oauth/agreement',{'client_id':client_id,'redirect_uri':redirect_uri, 'state':state, 'reqInfo':reqInfo});
    return;
  }catch(e){
    console.log(e);
  }
}
/***************** 동의 후 code 생성  *******************/
exports.callback = async (req, res, next) => {

  /// 동의를 누른사람만 오기때문에 최초 1번만 온다. 
  /// 한번 동의를 누른사람은 여기로 오지 않는다. 
  try {
    const { client_id, redirect_uri, state, reqInfo } = req.body;
   
    // 인증절차를 거치지 않고 uri를 통해 바로 들어온 경우를 검증
    if(!reqInfo) {
      res.status(500).send('잘못된 접근입니다.');
      return;
    }

    const username = res.locals.user.username;  
    const oauth = await Oauth.findByClientId(client_id);
    const redirectUri = oauth.client.redirectUris;
    const member = await Member.findByUsername(username); 
    const hide = member.serialize();
    req.body = hide;

     
    const agree = true;  
    await member.updateOne({agree: agree});
    const code = await oauth.setBcrypt(Math.random().toString());
    const expiresAt = (Date.now() + 3600000 * 9) + (60 * 10000) //10분
    await oauth.updateByAuthCode(code,expiresAt,redirect_uri,username);
  
    res.redirect(`${redirectUri}?code=${code}&state=${state}`)
    return;

  }catch(e){
    console.log(e);
  }
}

exports.token = async (req, res, next) => {
  try {
    
    const {code, clientSecret, redirect_uri, client_id, grant_type, refreshToken} = req.body;
    let msg; 

    if(grant_type == 'code'){
       // 쿼리가 들어왔는지 확인한다. 
      if(!code || !clientSecret || !redirect_uri || !client_id) {
        res.status(500).send('필수 데이터가 존재하지 않습니다.');
        return;
      }

      //받아온 query의 정보와 모두 일치하는 클라이언트를 찾고(검증) code의 유효기간을 불러온다.
      const oauth = await Oauth.findByVerifyClient(req.body);

      if(!oauth) {
        msg = '받은 정보와 Client의 등록정보가 일치하지 않습니다.';
        res.redirect(`${redirect_uri}?accessFailMsg=${msg}`);
        return;
      }

      const username = oauth.authorizationCode.user;

      const expiresAt = new Date(oauth.authorizationCode.expiresAt).getTime();
      const now = Date.now() + 3600000 * 9;
      const acsTknExpiresAt = Date.now() + ((3600000 * 9) + (60 * 10000)) //10분
      const refTknExpiresAt = Date.now() + ((3600000 * 9) + (60 * 60 * 24 * 1000)) //1일
      if(expiresAt < now){
        msg = 'authorization_code의 유효시간(10분)이 만료되었습니다.';
        res.redirect(`${redirect_uri}?accessFailMsg=${msg}`);
        return;
      }
   
      //발급해 주기전에 기존에 토큰이 있는지 검사부터..
      //재발급
  
      // access token 생성
      const access_token = await oauth.generateAccessToken();
      // refresh token 생성
      const refresh_token = await oauth.generateRefreshToken();
      req.body = oauth.serialize();
      
      const member = await Member.findByUsername(username); 
      req.body = member.serialize();
  
      const token = {
        'accessToken': access_token,
        'acsTknExpiresAt':acsTknExpiresAt,
        'refreshToken': refresh_token,
        'refTknExpiresAt':refTknExpiresAt,
        'client':oauth.client.appName,
        '_id':member._id
      }
      await oauth.updateOne({'token':token});
    
      res.send({access_token:`${JSON.stringify(token)}`});
      return;

    }else if(grant_type == 'refresh_token') {

      jwt.verify(refreshToken, process.env.OAUTH_JWT_REFRESH_SECRET_KEY, async (err, decoded)=> {
        if(err){
          console.log(err);
          res.send({massage:'refreshToken이 만료되었습니다. 재로그인 해주세요.'});
          return;
        }
        if(decoded.id == client_id && decoded.secret == clientSecret){

          const oauth = await Oauth.findByUsername(decoded.user);
          const acsTknExpiresAt = Date.now() + ((3600000 * 9) + (60 * 10000)) //10분       
          const access_token = await oauth.generateAccessToken();
          const token = {
            'accessToken': access_token,
            'acsTknExpiresAt':acsTknExpiresAt
          }     
          await oauth.updateOne({'token':token});
          res.send({access_token:`${JSON.stringify(token)}`});
          return;
        }else {
          console.log(err);
          res.send({massage:'검증 쿼리와 토큰의 정보가 일치하지 않습니다.'});
          return;
        }
      })
      
    }
  }catch(e){
    console.log(e);
  }
}
