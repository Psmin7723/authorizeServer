
  const Joi = require('joi');
  const Member = require('../../models/member');
  

  exports.registerView = async (req,res,next) => {
   
    if(res.locals.user){
      res.redirect('/oauth/regapp');
      return;
    }

    res.render('auth/register');
  }
  exports.userRegister = async (req,res,next) => {
    try{
      
      const {username, password, email, name} = req.body;
      const redirect = '/login';

      if(!username || !password || !email) {
        res.send({msg:false, valid:500});
        return;
      }
      const schema = Joi.object().keys({
        username: Joi.string()
          .alphanum()
          .min(3)
          .max(20)
          .required(),
        password: Joi.string().required(),
        name: Joi.string(),
        email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
        .required(),
      });
     
      const result = await Joi.validate(req.body, schema);
      if(result.error){
        res.send({msg:false, valid:400});
        return;
      }
      const exists = await Member.findByUsername(username);
      if(exists || exists != null) {
        res.send({msg:false, valid:409});
        return;
      }      
      let member = new Member({
        username,
        email,
        name,
        agree: false,
      })
      let clientRandom = Math.random().toString();
      await member.setClientId(clientRandom);
      await member.setClientSecret(clientRandom);
      await member.setPassword(password);
      await member.collection.createIndex( { "username": 1 }, { unique: true } )
      await member.save();
      const token = await member.generateToken(); 
      const hide = member.serialize();
      req.body = hide;
      await res.cookie('access_token', token,{
        maxAge: 1000 * 60 * 60 * 24 * 3,
        httpOnly: true,
      })
      res.send({msg:true, redirect:redirect});
     
    }catch(e){
      console.log(e);
    }
  }

  exports.loginView = async (req, res, next) => {
    if(res.locals.user){
      res.redirect('/oauth/regapp');
      return;
    }
    res.render('auth/login');
  }

  exports.userLogin = async (req, res, next) => {
    try{
      const {username, password} = req.body;   
      const redirect = '/oauth/regapp'; 
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
      const token = await member.generateToken(); 
      const hide = member.serialize();
      req.body = hide;
      await res.cookie('access_token', token,{
        maxAge: 1000 * 60 * 60 * 24 * 3,
        httpOnly: true,
      })
      await res.send({msg:true, redirect:redirect});
    }catch(e){
      console.log(e);
    }
  }

  exports.userLogout = async (req, res, next) => {
    res.cookie('access_token');
    res.status = 204;
    res.redirect('/');
  }





  
