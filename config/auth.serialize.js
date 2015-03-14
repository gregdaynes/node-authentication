// !IMPORTS
// =============================================================================
// app modules
var User             = require('../app/models/user');

// expose this function to our app using exports
module.exports = function(passport) {

    // Passport Session Setup
    // ----------------------
    // required for persistent login sessions
    // passport needs the ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });
}
