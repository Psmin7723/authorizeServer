
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { Schema } = mongoose;
const jwt = require('jsonwebtoken');
const {ACCESS_TOKEN, REFRESH_TOKEN, OAUTH_JWT_ACCESS_SECRET_KEY, OAUTH_JWT_REFRESH_SECRET_KEY } = process.env;

const authSchema = new Schema({
  authorizationCode: {    // code를 신청하는 client 계정에서 생성된다. 
    authorizationCode: String, // accessToken을 신청하기 위해 사용되는 code.
    expiresAt: {
      type:Date, // 만료기간 10분, rfc6749문서 권장
    }, 
    redirectUri: String, // 인증을 마치고 code가 반환되는 callback 주소
    user: String, // oauth서버에 로그인한 사용자(clientx)
  },
  client: { 
    clientId: String, // oauth2.0을 사용하겠다고 등록한 client의 clientId
    clientSecret: String, // clientSecret token생성때 전달 받는다. 
    grants: [], // grant에 따라 인증방식이 바뀌는데, 현재는 grant_code방식만 구현했기 때문에 사용되지 않음
    redirectUris: String, // client가 사용하겠다고 등록한 callback 주소
    reqInfo: {}, // client가 요구한 user의 정보 범위
    appName: String, // client의 어플리케이션 이름
    homepageAddr: String, // client의 웹 주소 referer 인증에 사용.
    username: String, // client의 oauthServer ID
  },
  token: {
    accessToken: String, // reqInfo 또는 resourceServer의 api를 사용하기 위해 필요한 Token
    acsTknExpiresAt: {
      type:Date, // 만료기간 1시간, rfc6749문서 권장
    },
    refreshToken: String, // accessToken이 만료 되었을때 새로 갱신하기 위한 Token
    refTknExpiresAt: {
      type:Date, // 만료기간 1일, 만료기간이 다 된다면 재로그인 하여 재발급
    },
    client: String, // 현재 해당 토큰에 연결되어 있는 client
    _id: mongoose.Types.ObjectId, // 현재 해당 토큰에 연결되어 있는 client의 고유 id
  }},
  {
  timestamps: { currentTime: () => Date.now() + 3600000 * 9 }
});

authSchema.statics.findByUsername = function(username) {
  return this.findOne({'client.username': username});
}
authSchema.statics.findByClientId = function(client_id) {
  return this.findOne({'client.clientId':client_id},{'client.clientSecret': false});
}
authSchema.statics.findByVerifyClient = function(data) {
  return this.findOne({
    'client.clientId':data.client_id,
    'client.clientSecret':data.clientSecret,
    'client.redirectUris':data.redirect_uri,
    'authorizationCode.authorizationCode':data.code
  });
}
authSchema.statics.findByAccesstoken = function(token) {
  return this.findOne({'token.accessToken':token},{'client.clientSecret': false});
}
authSchema.methods.setBcrypt = async function(code) {
  const hash = await bcrypt.hash(code, 10);
  return hash;
};
authSchema.methods.updateByAuthCode = function(code,expiresAt,redirect_uri,username) {
  return this.updateOne( {'authorizationCode':{
    'authorizationCode': code,
    'expiresAt':expiresAt,
    'redirectUri': redirect_uri,
    'user': username
  }})
} 
authSchema.methods.serialize = function(){
  const data = this.toJSON();
  delete data.client.clientSecret;
  return data;
}
authSchema.methods.generateAccessToken = function(){
  const token = jwt.sign(
    {
      id: this.client.clientId,
      secret: this.client.clientSecret,
      user: this.authorizationCode.user      
    },
    OAUTH_JWT_ACCESS_SECRET_KEY,
    {
      expiresIn: ACCESS_TOKEN,
    },
  );
  return token;
}
authSchema.methods.generateRefreshToken = function(){
  const token = jwt.sign(
    {
      id: this.client.clientId,
      secret: this.client.clientSecret,
      user: this.authorizationCode.user
    },
    OAUTH_JWT_REFRESH_SECRET_KEY,
    {
      expiresIn: REFRESH_TOKEN,
    },
  );
  return token;
}

module.exports  = mongoose.model('oauth', authSchema);



