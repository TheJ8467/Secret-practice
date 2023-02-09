//jshint esversion:6
const dotenv = require("dotenv");
dotenv.config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const FacebookStrategy = require("passport-facebook");

const app = express();

app.set("view engine", "ejs");
mongoose.set("strictQuery", true);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({ secret: "My secret.", resave: false, saveUninitialized: false })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  GoogleId: String,
  FacebookId: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
      enableProof: true,
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app
  .route("/register")

  .post(function (req, res) {
    User.register(
      { username: req.body.username },
      req.body.password,
      function (err, user) {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

app
  .route("/secrets")

  .get(function (req, res) {
    if (req.isAuthenticated()) {
      res.render("secrets");
    } else {
      res.redirect("/login");
    }
  });

app
  .route("/login")

  .post(function (req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    req.login(user, function (err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local", function (err, user, info) {
          if (err) {
            console.log(err);
          } else {
            res.redirect("/secrets");
          }
        })(req, res);
      }
    });
  });

app
  .route("/logout")

  .get(function (req, res) {
    req.logout(function (err) {
      if (!err) {
        res.redirect("/");
      }
    });
  });

app
  .route("/auth/google")
  .get(passport.authenticate("google", { scope: ["profile"] }));

app
  .route("/auth/google/secrets")

  .get(
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
      res.redirect("/secrets");
    }
  );

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

//
//
//
//
//

app.listen(3000, function () {
  console.log("Server started on port 3000");
});
