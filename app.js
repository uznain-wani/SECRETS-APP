
require ("dotenv").config();                   //keep this on top always for requiring .env file
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy; //for using oAuth
const findOrCreate =require("mongoose-findorcreate");
//const encrypt =require("mongoose-encryption");
//const md5 = require('md5');    //for md5hashing method of  passwords for security
//const bcrypt = require('bcrypt');     //for using becrypt hashing ,,,,,check docum for details
//const saltRounds = 10;

const app = express();
//console.log(process.env.SECRET);   //for acessing our secret in .env file

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
//its is imp to place session making here in code
app.use(session({         //setting up our session or initializing session
    secret: 'This is our little secret.',
    resave: false,
    saveUninitialized: true,
  }));

  //next step is to use passport,,,,, sequence must be same in code
  app.use(passport.initialize());  //initilized passport
  app.use(passport.session());        //use passport dealing with sessions

mongoose.set("strictQuery", false);
mongoose.connect("mongodb://127.0.0.1:27017/usersDB");
const userSchema = new mongoose.Schema( {   //for using mongoose encryption we changed sytax in schema and added new mongoose.Schema
  email: String,
  password: String,
  googleId:String , //we need to acess it in findor create function for matching users from dbase in logging in via google
  secret:String   //for storing new secret
});
// Passport-Local Mongoose is a Mongoose plugin that simplifies building username and password login with Passport.
userSchema.plugin(passportLocalMongoose);  //for enabling passport-local- mongoose  .
userSchema.plugin(findOrCreate);   //to use findorcreate function

///////////for encrypting password in binary data  syntax is////////////////////
//environment variables or .env are files that keep certainn sensitive variables  such as encryption keys and api keys  to keep them safe and secure off the internet///
//for this run "npm i dotenv" in CMD//

//const secret ="This is little secret.";  we will keep our thus secret in .env file for keeping it secure and safe
///////////////////////////////////// for using mongoose encryption//////////////////////////////
 //userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields: ["password"]});

const User = mongoose.model("User", userSchema);
////using passport-local mongoose  now here to create login strategy

passport.use(User.createStrategy());       /////  to create a local login strategy
 //this serial decerialize  codewill work for all strategies not only local
 passport.serializeUser(function(user, done) {
      done(null,user.id)  
    });
  
  passport.deserializeUser(function(id, done) {
   User.findById(id, function(err,user){
    done(err, user);
   });   
});
 

//passport.serializeUser(User.serializeUser()); //creates fcookie and fills info in it of logged in data
//passport.deserializeUser(User.deserializeUser()); ///crumbles this cookie upon logout

//for using oauth for logging in via google ,,steps are copied from passport doc for logging in via google starategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,   //from env file 
    clientSecret: process.env.CLIENT_secret,   //from env file
    callbackURL: "http://localhost:3000/auth/google/secrets" , //copy authorized redirect URI from project createdin google console
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //install findorcreate function via cmd and then require it and then u can use it here
    User.findOrCreate({ googleId: profile.id }, function (err, user) {  //here id is used to check from db so that everytime we login new entry dosent enter into dbase and it recognises us
      return cb(err, user);
    });
  }
));
  

app.get("/",function(req,res){
    res.render("home")
});

 // authenticate via passport using google type strategy 
 app.get("/auth/google",         //auth/google is the href in button of google in register.ejs and login .ejs and it will take them to login via google window
 passport.authenticate('google', { scope: ['profile'] }));         //coped from passport docs

//upon loggin in via google its will take to secrets page via this code 
  app.get('/auth/google/secrets', 
   passport.authenticate('google', { failureRedirect: "/login" }),
   function(req, res) {
   // Successful authentication, redirect home.
     res.redirect("/secrets");
   });


app.get("/login",function(req,res){
    res.render("login")
});
app.get("/register",function(req,res){
    res.render("register")
});
app.get("/logout",function(req,res){
  req.logout(function(err){
    if(err){
        console.log(err);
    }else{
        res.redirect("/");
    }
  });
});
app.get("/secrets",function(req,res){
    //display everyones secrets that what ever is in secrets field in dbase display that
   User.find({"secret":{$ne:null}},function(err,foundusers){ //find documents where secret field is not equal to null
    if(err){
        console.log(err);
    }else{
        if(foundusers){
            res.render("secrets",{userWithSecrets:foundusers})
        }
    }
   
   });
   
   
});

app.get("/submit",function(req,res){
    //check if user is logged in take him to submit page
    if(req.isAuthenticated()){
        res.render('submit');
       }else{
        res.redirect("/login")
       }
});
//for catching secret of user from submit.ejs
app.post("/submit",function(req,res){
   const submittedSecret= req.body.secret;
   //find user by his id in dbase and save his secret to his document in dbase
   User.findById(req.user.id, function(err,founduser){
     if(err){
        console.log(err);
     }else{
        founduser.secret= submittedSecret;
        founduser.save(function(){
            res.redirect("/secrets");
        })
     }
   });


});
app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
  });
//////////////////for using passport auth  we use different  content in login and register app.post as per its modules documentation/////
app.post("/register",function(req,res){
    //using passport-local-mongoose to register or creating a new user  
    User.register({username:req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
 // authenticating  the user using passport via local strategy and setting up loggin session for him,setting up a cookie and they should automtaically remain logged in 
             passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
             })
        }
    })


});
app.post("/login",function(req,res){
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });
   // using passport to check if user is already registered and log him in
   req.login(user,function(err){
    if(err){
        console.log(err);
    }else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        });
    }
   });

});











/*app.post("/register",function(req,res){
   // using becrypt hashing and storing hash in dbase
   bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    // add a new user to our dbase
 const newUser = new User({
    email:req.body.username,
    password:hash    //generated hash
    // password: md5(req.body.password)
    ////////////////////////////md5 encryption using hashing our messages///////////////////////////
    //generated hash of our password lways remains same  /////////
   });
newUser.save(function(err){
    if(err){
        console.log(err);
    }else{
        res.render("secrets");  // if they register then only take them to secrets page 
    }
});
});    
});
app.post("/login",function(req,res){
    const username = req.body.username;
   // const password =md5(req.body.password);
   const password =req.body.password;  
   // check if he is registered user from our db  then log him in secrets page

    User.findOne({email:username},function(err,founduser){ // check if typed username matches  our dbase email
        if(err){
            console.log(err);
        }else{
            //if(founduser.password===password){  //then also check its password with our db password and give him acess to secrets page
            bcrypt.compare(password,founduser.password, function(err, result) {
                if(result===true){
                    res.render("secrets");
                }
            });   
           // }
        }
    });
});*/
    
app.listen(3000, function() {
    console.log("Server started on port 3000");
  });

// hashing and salting: hashing is when we  run our password via hash function and covert it into hash and store it into our dbase 
//salting is generating a random set of characters(different each time) along with our password and then passing both via hash function and generate  our hash//
//salting increases characters and complexity of our paswword and make it more secure
//bcrypt is one of the hashing algorithms just like md5 algorithm that is used to increase security more and is more efficient 
//we can generate 20billion md5hashes/sec ,so even though we add salts hackers still can generate hash tables with all salt combinations quickly
//but with bycrypt(17000bycrypt hashes/sec) we can slow it down and hence increase security,hackers can only generate 170000 hashes per sec in this even using latest technology
//bycrypt has a concept of salt rounds,the more rounds we do more saltier and complex and secure our password
// password+salt1=hash1 (round1) =>hash1+salt1=hash2(round2) So,here we add same salts to generated hashs and these are termed as rounds 
//decrypt works on stable versions only that is even versions ,check ur stable version node.js website on L.H.S,now if current version is odd ,
//go to stable version using nvm command for  which command  can be checked in nvm git repository and after ruuning that command check its version and then
//install stable version using "nvm install10.15.0" etc and it will be downloaded  and then run becrypt command npm i becrypt

////////////////////////////////////// COOKIES AND SESSIONS AND PASSPORT////////////////////////////////////
// when we save something in cart and leave amazon then amazon save cookies in our browser which contains some id ,data of that item so that when 
// we open amazon again ,item is still in cart ,if we clear its cookies in browser item wont be in cart .coookies are of manytypes
// here we will discuss cookies that are used toestablish and mainatain sessions ,sessions is a peruios of time browser interacts with server
//when we login in wesite thats when session starts and fortune cookie gets created which contains our login credentials and we wont be asked to login until we logout
//bcause they can always check against that cookie and it maintains our authenticationfor this browsing session until logout when this cookie gets destroyed
//we implement cookies and sessions using somthing called passport which is authentication middleware for node.js,which includes a comprehensive
//set of strategies to suppport authentication like simple  username  and password,or more secure like via fbook ,twitter or google etc
//check passport .org doc for authenticating via login logout ,login via  fbook or google etc
//for using passport auth procedures  we need to install some packages of npm : npm i passport,passport-local,passport-local-mongoose,express-session
//each of these packages have their documentation for their implentation

//////////////////////////   ////   OAuth :open standard for token based authorization//////////////////////////////////
// by using oauth we are able to acess pieces of info on third party websites like friends on facebook ,friends on gmail 
// like in some new app when we login via facebook we get acess to our facebook friends on this new app (who use our new app also) and we can add thm here also,this is possible via oauth
// similarly  in security oauth also plays an imp role by sighning via fbook googlesuch as delegating the task of managing passwords securely to big companise lile fb google
// we usually have login by google ,login by facebook etc on websites which enable us to incresase security by logging via them as we get acees to their secure methods 
// but for this we use oAuth which acts as a gule and binds thsi together and makes it work
//oauth has 3 specialities:granualrity,read/write acess,revoke that acess
//for implementing oauth  via google facebook etc check doc of passportjs.org and select strategy and follow steps