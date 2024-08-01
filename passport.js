const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const helper = require("../helpers/helper");

// Set up the Passport strategy:
passport.use(new LocalStrategy(
  async function(username, password, done) {
    helper.findByUsername(username, async (err, user) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      const matchedPassword = await bcrypt.compare(password, user.password);
      if (!matchedPassword) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      return done(null, user);
    });
  }
));

// Serialize a user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize a user
passport.deserializeUser((id, done) => {
  // Call helper.findById to retrieve the user based on the ID
  helper.findById(id, (err, user) => {
    if (err) {
      return done(err); // Pass the error to done if found
    }
    done(null, user); // Call done with error and user
  });
});
