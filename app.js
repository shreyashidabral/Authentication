//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

const encrypt = require("mongoose-encryption"); //Level 2 authentication  --encrypting pass
const md5 = require("md5"); //Level 3 authentication  --hashing pass
const bcrypt = require("bcrypt"); //Level 4 authentication  --salting and hashing pass
// const saltRounds = 10;

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({ //Setting up/configuring our session
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
    password: String
});

//Plugins : extended bits of packaged code added to mongoose schema to give them more functionality
userSchema.plugin(passportLocalMongoose); //used for salting, hashing and saving new users in db

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// ****** Get and Post requests ********

app.get("/", function(req, res) {
    res.render("home");
});

app.route("/register")
    .get(function(req, res) {
        res.render("register");
    })

    .post(function(req, res) {
            User.register({username: req.body.username}, req.body.password, function(err, user) {
                if (err) {
                    console.log(err);
                    res.redirect("/register");
                } else { //if there are no errors we wlll authenticate the user
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
