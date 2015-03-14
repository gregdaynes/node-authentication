// !IMPORTS
// =============================================================================
// npm modules
var LocalStrategy    = require('passport-local').Strategy;

// app modules
var config           = require('./index.js');
var User             = require('../app/models/user');


// expose this function to our app using exports
module.exports = function(passport) {

    // Local Signup
    // ------------------------
    // we are using named strategies since we have on for login and one for
    // signup by default, if there was no name, it would just be called 'local'
    passport.use('local-signup', new LocalStrategy({

        // by default, local strategy uses username and password, we will override with e-mail
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire request to the callback
    },

    function(req, email, password, done) {

        // Use lower-case e-mails to avoid case-sensitive e-mail matching
        if (email) {
            email = email.toLowerCase();
        }

        // async
        process.nextTick(function() {

            // if the user is not alreayd logged in
            if (!req.user) {
                // User.findOne wont fire until data is sent back
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
            }

            // if the user is logged in but has no account
            else if (!req.user.local.email) {

                // looking for a local account
                // lets check if the email used to connect a local account is being usd
                User.findOne({ 'local.email': email }, function(err, user) {

                    if (err) {
                        return done(err);
                    }

                    if (user) {
                        // Using 'loginMessage instead of signupMessage because it's used by /connect/local'
                        return done(null, false, req.flash('loginMessage', 'That email is already taken.'));
                    }

                    //
                    else {
                        var user = req.user;
                        user.local.email = email;
                        user.local.password = user.generateHash(password);
                        user.save(function(err) {
                            if (err) {
                                return done(err);
                            }
                            return done(null, user);
                        });
                    }
                });
            }

            // user is logged in and already has a local account
            else {
                return done(null, req.user);
            }
        });
    }));

    // Local Login
    // ------------------------
    // we are using named strategies since we have one for login and one for
    // signup by default, if there was no name, it would just be called local
    passport.use('local-login', new LocalStrategy({

        // by default local strategy uses username and password - override with email
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire requ
    },

    // callback with email and password from form
    function(req, email, password, done) {

        // Use lower-case e-mails to avoid case-sensitive e-mail matching
        if (email) {
            email = email.toLowerCase();
        }

        // async
        process.nextTick(function() {

            // find a user whose email is the same as the form's email
            // we are checking to see if the user trying to login already exists
            User.findOne({ 'local.email': email }, function(err, user) {

                // return any errors
                if (err) {
                    return done(err);
                }

                // if no user is found, return the message
                if (!user) {
                    // req.flash is the way to set flashdata using connect-flash
                    return done(null, false, req.flash('loginMessage', 'no user found.'));
                }

                // if user found but wrong password
                if (!user.validPassword(password)) {
                    // create the loginMessage and save it to session as flash data
                    return done(null, false, req.flash('loginMessage', 'oops! wrong password.'));
                }

                // all good, return success
                else {
                    return done(null, user);
                }
            });
        });
    }));
};
