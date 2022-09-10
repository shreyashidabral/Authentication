//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate")

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({                 //Setting up/configuring our session
    secret: "Our little secret.", //any secret string to be saved in .env file
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize()); //setting up or initializing passport package to start using it for authentication
app.use(passport.session()); //using passport to set up our session

// Database connection

mongoose.connect("mongodb://localhost:27017/secretDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId : String
});

//Plugins : extended bits of packaged code added to mongoose schema to give them more functionality
userSchema.plugin(passportLocalMongoose); //used for salting, hashing and saving new users in db
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// ****** Get and Post requests ********

app.get("/", function(req, res) {    //root route or home page
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {             // Successful authentication, redirect to any priviledged page.
        res.redirect("/secrets");
});

app.route("/register")              //register route
    .get(function(req, res) {
        res.render("register");
    })

    .post(function(req, res) {
            User.register({username: req.body.username}, req.body.password, function(err, user) {
                if (err) {
                    console.log(err);
                    res.redirect("/register");
                } else { //if while registering there are no errors we wlll authenticate the user
                    passport.authenticate("local")(req, res, function() { //type of authentication - local strategy
                        res.redirect("/secrets");
                        //this callback will only by triggered if the authentication was succesful,
                        //we set up a cookie, saved their current logged in session
                        //then we can redirect them to the secrets page successfully
                    })
                }
            }
        )
    });

app.route("/login")
    .get(function(req, res) {
        res.render("login");
    })

    .post(function(req, res) {
        const user = new User({
            username : req.body.username,
            password : req.body.password
        })

        req.login(user, function(err){    //login method of passport
            if(err){
                console.log(err);
            }else{      //if no errors - that means the user have successfully logged in and we'll authenticate the user
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                })
            }
        })
    });

app.route("/secrets")       //with cookies and session we can access secrets page directly when we are still logged in
    .get(function(req, res){   //to get secrets page directly we will first check if the user is authenticated
        if(req.isAuthenticated()){
            res.render("secrets");
        }else{              //if user is not authenticated redirect them to login route
            res.redirect("login");
        }
    })

    .post(function(req, res){

    });

app.route("/logout")    //deauthenticate the user and end the session
    .get(function(req, res){
        req.logout(function(err){
            if(err){
                console.log(err);
            }else{
                res.redirect("/");
            }
        });
    });

app.listen(3000, function() {
    console.log("Server started successfully.");
})
