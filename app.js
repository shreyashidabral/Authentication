//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption"); //Level 2 authentication  --encrypting pass
const md5 = require("md5"); //Level 3 authentication  --hashing pass
const bcrypt = require("bcrypt"); //Level 4 authentication  --salting and hashing pass
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

// Database connection

mongoose.connect("mongodb://localhost:27017/secretDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

//Plugins : extended bits of packaged code added to mongoose schema to give them more functionality
//fetching secretkey from .env file
// userSchema.plugin(encrypt, {secret : process.env.SECRET, encryptedFields : ['password'] });

const User = new mongoose.model("User", userSchema);


// ****** Get and Post requests ********

app.get("/", function(req, res) {
    res.render("home");
});

app.route("/register")
    .get(function(req, res) {
        res.render("register");
    })

    .post(function(req, res) {
        bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
            const newUser = new User({
                email: req.body.username,
                password: hash
            })
            newUser.save(function(err) {
                if (!err) {
                    res.render("secrets");
                } else {
                    console.log(err);
                }
            });
        });
    });

app.route("/login")
    .get(function(req, res) {
        res.render("login");
    })

    .post(function(req, res) {
        const username = req.body.username;
        const password = req.body.password;

        User.findOne({
            email: username
        }, function(err, foundUser) {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    bcrypt.compare(password, foundUser.password, function(err, result) {
                        if (result === true) {
                            res.render("secrets");
                        } else {
                            console.log(err);
                        }
                    });
                }
            }
        });
    });

app.listen(3000, function() {
    console.log("Server started successfully.");
})
