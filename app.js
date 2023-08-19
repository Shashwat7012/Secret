require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
//we are using bcrypt js instead of bcrypt due to installing issues.
// const bcryptJs = require('bcryptjs');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');



const app = express();

// console.log(process.env.SECRET);

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded ({
    extended: true
}));

//documentation
app.use(session({
    secret :"Our Little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true});

//For basic
// const userSchema ={
//     email: String,
//     password: String
// }

//for Encryption
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    //2ndly
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


//encryption.

// userSchema.plugin (encrypt, {secret:process.env.SECRET, encryptedFields:['password']});

// The plugin encrypts the specified fields before saving them to the database and decrypts them when reading from the database.
// secret: This is the encryption secret that is used to encrypt and decrypt the data. It's a secret key that you should keep secure.
// encryptedFields: This is an array of field names that you want to encrypt. In this case, you are encrypting only the password field.
// In modern web development, using libraries like bcrypt or exploring more advanced security options like JSON Web Tokens (JWT) for authentication is recommended.


const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
// passport.serializeUser(User.serializeUser());
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
    try {
        const user = await User.findById(id).exec();
        done(null, user);
    } catch (err) {
        console.log("Error:", err);
        done(err, null);
    }
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  async function(accessToken, refreshToken, profile, cb) {
    try {
      console.log(profile);
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = new User({ googleId: profile.id });
        await user.save();
      }

      return cb(null, user);
    
// This line invokes the callback function with the error (err) as the first argument and null as the second argument.
// This handles any errors that occurred during the asynchronous operations and passes them to the callback for handling.
    } catch (err) {
      return cb(err, null);
    }
  }
));



app.get("/",(req,res)=>{
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });





app.get("/login",(req,res)=>{
    res.render("login");
});

app.get("/register",(req,res)=>{
    res.render("register");
});

// app.post("/register", async (req, res) => {
//     try {
//       // Hash the password using bcryptJs
//       const hashedPassword = await bcryptJs.hash(req.body.password, saltRounds);
  
//       const newUser = new User({
//         email: req.body.username,
//         password: hashedPassword // Store the hashed password in the database
//       });
  
//       await newUser.save();
//       res.render("secrets");
//       console.log("User Registered Successfully");
//     } catch (err) {
//       console.log("Error:", err);
//       res.send("Error registering user");
//     }
//   });
  
//   app.post("/login", async (req, res) => {
//     const username = req.body.username;
//     const userProvidedPassword = req.body.password; // Get the user's input password
  
//     try {
//       const found = await User.findOne({ email: username });
  
//       if (found) {
//         // Compare the provided password with the stored hash using bcryptJs.compare
//         const passwordMatch = await bcryptJs.compare(
//           userProvidedPassword,
//           found.password
//         );
  
//         if (passwordMatch) {
//           console.log("Password match: User is authenticated.");
//           res.render("secrets");
//         } else {
//           console.log("Incorrect password");
//           res.send("Incorrect password");
//         }
//       } else {
//         console.log("User not found");
//         res.send("User not found");
//       }
//     } catch (err) {
//       console.log(err);
//       res.send("An error occurred");
//     }
//   });

app.get("/secrets", async (req, res) => {
    try {
        const found = await User.find({"secret": {$ne: null}}).exec();

        if (found) {
            res.render("secrets", { usersWithSecrets: found });
        }
    } catch (err) {
        console.log(err);
    }
});


app.get("/submit",(req,res)=>{
    if (req.isAuthenticated()){
        res.render("submit");
    } else{
        res.redirect("/login");
    }
});

app.post("/submit", async (req, res) => {
    const submittedSecret = req.body.secret;

    try {
        //req.user.id is a functinality of passport.
        const found = await User.findById(req.user.id).exec();

        if (found) {
            found.secret = submittedSecret;
            await found.save();
            res.redirect("/secrets");
        }
    } catch (err) {
        console.log(err);
    }
});


app.get("/logout",(req,res)=>{
    req.logOut(()=>{
        res.redirect("/")
    })

});

//cookie and session
app.post("/register", async (req,res)=>{

    User.register({username: req.body.username}, req.body.password, async (err, user) => {
    
        try{
            if(err){
               await console.log(err);
                res.redirect("/register");
            }
            else{
                passport.authenticate("local")(req,res, async()=>{
                    await res.redirect("/secrets")
                })
            }
        } catch{
            console.log("Something Went Wrong")
        }

    })
})


app.post("/login", async (req,res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.username
    });

    req.login(user,  async (err)=>{
        try{
            if(err){
                console.log(err);
            }
            else{
                passport.authenticate("local")(req,res, async()=>{
                    await res.redirect("/secrets")
            })
        }
    } catch{
        console.log("Error");
    }
    })
})
  

//Level-2 :- Encryption
// Simple encryption and authentication for mongoose documents. Relies on the Node crypto module. Encryption and decryption happen transparently during save and find. 

//Level-3 :- Hashing

//Level-4 :- Salting and Hashing(bcrypt) but due to installing issues. we have to install bcryptjs.

//Level-5 :- cookie and session (using passport( :- notes))

app.listen(3000, ()=>{
    console.log("Server started on port 3000");
})