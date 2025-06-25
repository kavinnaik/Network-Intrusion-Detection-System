// jshint esversion:6

require('dotenv').config();
const homeRoute = require('./routes/home');
const currentYear = new Date().getFullYear();
const { parse, stringify } = require('flatted');
let { PythonShell } = require('python-shell');
const express = require("express");
const multer = require('multer');
const download = require('download');
const fs = require('fs');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();
const path = require("path");
app.locals.currentYear = new Date().getFullYear();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.set("views", path.join(__dirname, "views"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/home', homeRoute);


// Configure express-session *before* Passport.js
app.use(session({
  secret: process.env.SESSION_SECRET || "yourfallbacksecret",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.DB_URI)
    .then(() => console.log("MongoDB connected successfully!"))
    .catch((err) => {
      console.error("MongoDB connection error:", err);
      console.error("Full error object:", err);  // Log the entire error object
    });
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  googleProfile: {    // Store Google Profile info (optional)
    id: String,
    displayName: String,
    emails: [ { value: String } ],
    photos: [ { value: String } ],
  }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// Serialize and deserialize users
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then(user => {
      done(null, user);
    })
    .catch(err => {
      done(err, null);
    });
});


passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALL_BACK_URL || 'http://localhost:4000/auth/google/callback',
  userProfileURL: process.env.URL || 'https://www.googleapis.com/oauth2/v3/userinfo',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value || 'no-email@example.com';
    const displayName = profile.displayName || 'Unknown';

    // Check if user with this Google ID exists
    let user = await User.findOne({ googleId: profile.id });

    if (user) {
      return done(null, user);
    }

    // Check if a user already exists with the same email/displayName
    const existingUsernameUser = await User.findOne({ username: email });

    if (existingUsernameUser) {
      // Update that user to attach Google ID
      existingUsernameUser.googleId = profile.id;
      existingUsernameUser.googleProfile = {
        id: profile.id,
        displayName,
        emails: profile.emails || [],
        photos: profile.photos || [],
      };

      await existingUsernameUser.save();
      return done(null, existingUsernameUser);
    }

    // Create new user
    user = new User({
      username: email,
      email,
      googleId: profile.id,
      googleProfile: {
        id: profile.id,
        displayName,
        emails: profile.emails || [],
        photos: profile.photos || [],
      },
    });

    await user.save();
    return done(null, user);

  } catch (err) {
    console.error("Google login error:", err);
    return done(err, null);
  }
}));




let submitted_csv_file = "";
const storage = multer.diskStorage({
  destination: (req, file, callback) => callback(null, './Uploaded_files'),
  filename: (req, file, callback) => {
    submitted_csv_file = file.originalname;
    console.log(submitted_csv_file);
    callback(null, file.originalname);
  }
});

const upload = multer({ storage: storage }).single('myfile');

// --- Routes ---
app.get("/", (req, res) => res.render("home"));
app.get("/secrets", (req, res) => res.render("secrets"));
app.get("/secrets_2", (req, res) => {
  res.render("secrets_2", {
    knn_desc: "K-Nearest Neighbors (KNN) is a simple, yet powerful classification algorithm. It classifies data points based on the majority class of their k-nearest neighbors.",
    knn_bin_acc: "85.67%", // Binary classification accuracy
    knn_mul_acc: "78.34%", // Multi-class classification accuracy
    knn_bin_cls: `
      <table class="table table-bordered">
        <thead>
          <tr><th>Label</th><th>Precision</th><th>Recall</th><th>F1-Score</th></tr>
        </thead>
        <tbody>
          <tr><td>Normal</td><td>0.87</td><td>0.83</td><td>0.85</td></tr>
          <tr><td>Intrusion</td><td>0.84</td><td>0.88</td><td>0.86</td></tr>
        </tbody>
      </table>
    `,
    knn_mul_cls: `
      <table class="table table-bordered">
        <thead>
          <tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1-Score</th></tr>
        </thead>
        <tbody>
          <tr><td>Normal</td><td>0.81</td><td>0.76</td><td>0.78</td></tr>
          <tr><td>DoS</td><td>0.79</td><td>0.80</td><td>0.80</td></tr>
          <tr><td>Probe</td><td>0.74</td><td>0.71</td><td>0.72</td></tr>
          <tr><td>R2L</td><td>0.65</td><td>0.60</td><td>0.62</td></tr>
          <tr><td>U2R</td><td>0.55</td><td>0.50</td><td>0.52</td></tr>
        </tbody>
      </table>
    `
  });
});

app.get("/paramsecrets", (req, res) => res.render("paramsecrets"));
app.get("/csv", (req, res) => req.isAuthenticated() ? res.render("csv") : res.redirect("/login"));
app.get("/features", (req, res) => res.render("features"));
app.get("/attacks", (req, res) => res.render("attacks"));
app.get("/about", (req, res) => res.render("about"));
app.get("/stats", (req, res) => res.render("stats"));
app.get("/parameters", (req, res) => res.render("parameters"));
app.get("/contact", (req, res) => res.render("contact"));

// Google OAuth routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/home');
  });


app.get("/login", (req, res) => {
    res.render("login"); // Just render the login page
});
app.get("/register", (req, res) => res.render("register"));
app.get("/submit", (req, res) => req.isAuthenticated() ? res.render("submit") : res.redirect("/login"));


app.get("/logout", (req, res) => {
  req.logout((err) => {  //Passport 0.6 requires passing a callback
    if (err) {
        console.log("Logout error", err);
        return next(err);
    }
    res.redirect("/");
    if (submitted_csv_file) {
      const path = `./Uploaded_files/${submitted_csv_file}`;
      fs.unlink(path, err => {
        if (err) console.log(err);
        console.log('File deleted');
        submitted_csv_file = "";
      });
    }
  });
});

app.post("/register", (req, res) => {
  User.register({ username: req.body.username }, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => res.redirect("/submit"));
    }
  });
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/home",
  failureRedirect: "/login"
}));


const PORT = process.env.PORT || 4000;

app.listen(PORT, function () {
  console.log(`Server started on port ${PORT}`);
});


app.get("/testdb", async (req, res) => {
  try {
    // Assuming you have a model named 'TestModel' and a database named 'testdb'
    const TestModel = mongoose.model('Test', new mongoose.Schema({ name: String }), 'tests'); // 'tests' is the collection name

    // Create a new document
    const newTestDocument = new TestModel({
      name: "Test Document " + new Date(),
    });

    // Save the new document to the database
    await newTestDocument.save();

    console.log("Successfully created and saved a test document.");
    res.status(200).send("Successfully created and saved a test document.");
  } catch (error) {
    console.error("Error creating and saving test document:", error);
    res.status(500).send("Error creating and saving test document: " + error.message);
  }
});



// Add to user schema
userSchema.plugin(findOrCreate);

const { spawn } = require("child_process");

// Your other app.get or app.post routes here...

app.get("/secrets_2", (req, res) => {
  const python = spawn("python", ["nids_random.py"]); // 👈 Make sure this is correct path to your .py file

  let result = "";

  python.stdout.on("data", (data) => {
    result += data.toString();
  });

  python.stderr.on("data", (data) => {
    console.error(`stderr: ${data}`);
  });

  python.on("close", (code) => {
    try {
      const parsed = JSON.parse(result);
      res.render("secrets_2", {
        knn_bin_cls: parsed.knn_bin_cls,
        knn_mul_cls: parsed.knn_mul_cls,
        knn_bin_acc: parsed.knn_bin_acc,
        knn_desc: parsed.knn_desc,
      });
    } catch (e) {
      console.error("Error parsing Python output:", e);
      res.status(500).send("Error parsing prediction");
    }
  });
});
