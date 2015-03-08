// !IMPORTS
// =============================================================================
var LocalStrategy = require('passport-local').Strategy;
var User          = require('../app/models/user');


// expose this function to our app using exports
module.exports = function(passport) {

    // Passport Session Setup
    // required for persistent login sessions
    // passport needs the ability to serialize and unserialize users out of session
    // ----------------------

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


    // Local Signup
    // we are using named strategies since we have on for login and one for signup by default, if there was no name, it would just be called 'local'
    // ------------------------

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with e-mail
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) {

        //asynchronous
        // User.findOne wont fire until data is sent back
        process.nextTick(function() {

            // find a user whose email is the same as the req email
            // we are checking to see if the user trying to login already exists
            User.findOne({ 'local.email': email }, function(err, user) {

                // return any errors
                if (err) {
                    return done(err);
                }

                // check to see if there's already a user with that email
                if (user) {
                    return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                } else {

                    // if there is no user with that email
                    // create the user
                    var newUser = new User();

                    // set the user's local credentials
                    newUser.local.email = email;
                    newUser.local.password = newUser.generateHash(password);

                    // save the user
                    newUser.save(function(err) {

                        if (err) {
                            throw err;
                        }

                        return done(null, newUser);
                    });
                }
            });

        });
    }));





    // Local Login
    // we are using named strategies since we have one for login and one for signup by default, if there was no name, it would just be called local
    // ------------------------
    passport.use('local-login', new LocalStrategy({

        // by default local strategy uses username and password - override with email
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire requ
    },
    function(req, email, password, done) { // callback with email and password from form

        //find a user whose email is the same as the form's email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'local.email': email }, function(err, user) {

            // return any errors
            if (err) {
                return done(err);
            }

            // if no user is found, return the message
            if (!user) {
                return done(null, false, req.flash('loginMessage', 'no user found.')); // req.flash is the way to set flashdata using connect-flash
            }

            // if user found but wrong password
            if (!user.validPassword(password)) {
                return done(null, false, req.flash('loginMessage', 'oops! wrong password.')); // create the loginMessage and save it to session as flash data
            }

            console.log('look at that, let\'s keep going');

            // all good, return success
            return done(null, user);
        });
    }));
};
