const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const saltRounds = 10;

const redirectLogin = (req, res, next) => {
  if (!req.session.userId) {
    res.redirect("./login"); // redirect to the login page
  } else {
    next(); // move to the next middleware function
  }
};

// GET route for rendering the registration form
router.get("/register", function (req, res, next) {
  res.render("register.ejs"); // Assuming you're using EJS templates
});

// POST route for handling user registration
router.post("/registered", function (req, res, next) {
  // Extract form data
  const { username, first_name, last_name, email, password } = req.body;

  // Hash the password
  bcrypt.hash(password, saltRounds, function (err, hashedPassword) {
    if (err) {
      return next(err); // Handle error
    }

    // SQL query to insert user data into the database
    let sqlquery = `INSERT INTO users (username, first_name, last_name, email, hashedPassword) VALUES (?, ?, ?, ?, ?)`;
    let newrecord = [username, first_name, last_name, email, hashedPassword];

    // Store the new record in the database
    db.query(sqlquery, newrecord, (err, result) => {
      if (err) {
        return next(err); // Handle SQL error
      }

      // Send confirmation to the user
      let responseMessage = `Hello ${first_name} ${last_name}, you are now registered! We will send an email to you at ${email}. `;
      responseMessage += `Your hashed password is: ${hashedPassword}`;

      res.send(responseMessage);
    });
  });
});
router.get("/list", redirectLogin, function (req, res, next) {
  // SQL query to select all users without their passwords
  let sqlquery = `SELECT username, first_name, last_name, email FROM users`;

  // Execute the query
  db.query(sqlquery, (err, result) => {
    if (err) {
      return next(err); // Handle SQL error
    }

    // Render the result to the users_list.ejs template
    res.render("users.ejs", { users: result });
  });
});

// GET route for rendering the login form
router.get("/login", function (req, res, next) {
  res.render("login.ejs"); // Render the login form
});
// POST route for handling login
router.post("/loggedin", function (req, res, next) {
  req.session.userId = req.body.username;
  // Extract form data
  const { username, password } = req.body;

  // SQL query to select user by username
  let sqlquery = `SELECT * FROM users WHERE username = ?`;

  // Execute the query
  db.query(sqlquery, [username], (err, results) => {
    if (err) {
      return next(err); // Handle SQL error
    }

    // If no user found, login fails
    if (results.length === 0) {
      return res.send("Login failed: Username not found.");
    }

    // User found, check password
    const user = results[0];
    bcrypt.compare(password, user.hashedPassword, function (err, match) {
      if (err) {
        return next(err); // Handle error
      }

      // If password matches
      if (match) {
        res.send(
          `Welcome back, ${user.first_name} ${user.last_name}! You are now logged in.`
        );
      } else {
        res.send("Login failed: Incorrect password.");
      }
    });
  });
});

// Export the router object so index.js can access it
module.exports = router;
