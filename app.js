//include dotenv to loads environment variables from a .env file process.env
require('dotenv').config();

//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
mongoose.set('useCreateIndex', true);
// For mongoose-encryption
//var encrypt = require('mongoose-encryption');

// for md5 hashing - level 3
const md5 = require("md5");

// Level 4 - salting, hasing with round numbers with bcrypt
const bcrypt = require("bcrypt");
const saltRounds = 10;


// For passport and session
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

// For Oauth 2
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// For findOrCreate on mongoose
findOrCreate = require('mongoose-findorcreate');

const app = express();
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
}))

// initialize passport for express application
app.use(passport.initialize());
app.use(passport.session());

// connect to the database
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  secrets: [String]
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// Encryption part with mongoose-Encryption
//var secret = process.env.SECRET;
//userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });
//

const User = new mongoose.model("User", userSchema);
// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());



// use static serialize and deserialize of model for passport session support
//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//Authorize then auto redirect to "/auth/google/secrets"
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

// Redirect to main page after login with google
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

// homepage
app.get("/", function(req, res){
  res.render("home");
});


app.route("/login").get(function(req, res){
  res.render("login");
})
.post(function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  })

  req.login(user, function(err){
    if(err){
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      })
    }
  })
});


app.route("/secrets")
.get(function(req, res) {
  if(req.isAuthenticated()){
    User.findById(req.user._id, function(err, foundUser){
      if(err){
        console.log(err);
      } else {
        res.render("secrets", {user: foundUser});
      }
    })

  } else {
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
    });
  }
});
// register
app.route("/register")
.get(function(req, res){
  res.render("register");
})
.post(function(req, res){
  User.register({username:req.body.username},
  req.body.password,
  function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.route("/logout")
.get(function(req, res){
  req.logout();
  res.redirect("/");
});


// Submit page
app.route("/submit")
.get(function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})
.post(function(req, res){
  User.findByIdAndUpdate(req.user._id,
    {
        "$push": { "secrets": req.body.secret}
    },
    { "new": true, "upsert": true },
    function (err, updatedUser) {
        if (err) {
          console.log(err);
        } else {
          console.log(updatedUser);
          res.redirect("/secrets");
        }
    }
  );
});

/*

// login
app.route("/login").get(function(req, res){
  res.render("login");
})
.post(function(req, res){
  User.findOne(
    {email: req.body.username},
    function(err, foundAccount){
      if(err){
        res.send(err);
      }else{
        if(foundAccount){
          bcrypt.compare(req.body.password, foundAccount.password, function(err, result) {
            // result == true
            if(result == true){
              res.render("secrets");
            } else {
              res.send("wrong pass");
            }
          });
      } else {
        res.send("Can't find account");
      }

    }
  })
});

// register
app.route("/register")
.get(function(req, res){
  res.render("register");
})
.post(function(req, res){
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
      if(err){
        res.send(err);
      }
      // Store hash in your password DB.
      const newUser = new User({
        email: req.body.username,
        password: hash
      });
      newUser.save(function(err){
        if(err){
          res.send(err);
        } else {
          res.render("secrets");
        }
      });
    });
});
*/



// Listen to our 3000 port
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function(res) {
  console.log("server running on port 3000");
})
