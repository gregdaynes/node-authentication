// !IMPORTS
// =============================================================================
// npm modules
var GoogleStrategy   = require('passport-google-oauth').OAuth2Strategy;

// app modules
var config           = require('./index.js');
var User             = require('../app/models/user');


// expose this function to our app using exports
module.exports = function(passport) {

    // Google
    // ------------------------
    passport.use(new GoogleStrategy({

        // pull in app id and secret from config
        clientID: config.googleAuth.clientId,
        clientSecret: config.googleAuth.clientSecret,
        callbackURL: config.googleAuth.callbackURL,
        passReqToCallback: true // allows us to pass in the req from our route (lets us check if user is logged in or not)
    },

    function(req, token, refreshToken, profile, done) {

        // async
        // findOne will wait until we have all the data from Google
        process.nextTick(function() {

            // check if user is already logged in
            if (!req.user) {

                // try to find the user based on their google Id
                User.findOne({ 'google.id': profile.id }, function(err, user) {

                    // stop everything for errors
                    if (err) {
                        return done(err);
                    }

                    if (user) {

                        // if there is a user id already but no token (user was linked and then removed)
                        // add our token and profile information
                        if (!user.google.token) {
                            user.google.token = token;
                            user.google.name = profile.displayName;
                            user.google.email = profile.emails[0].value;

                            user.save(function(err) {
                                if (err) {
                                    throw err;
                                }

                                return done(null, user);
                            });
                        }

                        // if user found, log them in
                        return done(null, user);
                    }

                    // no user, create one
                    else {

                        var newUser = new User();

                        // set all the relevant information we will need
                        newUser.google.id = profile.id;
                        newUser.google.token = token;
                        newUser.google.name = profile.displayName;
                        newUser.google.email = profile.emails[0].value; // first email


                        // save new user to db
                        newUser.save(function(err) {
                            if (err) {
                                throw err;
                            }

                            return done(null, newUser);
                        });
                    }
                });
            }

            // user already exists and is logged in
            // lets link the accounts
            else {

                var user = req.user; // pull the user out of the session

                // update the current users google credentials
                user.google.id = profile.id;
                user.google.token = token;
                user.google.name = profile.displayName;
                user.google.email = profile.emails[0].value;

                // save the user
                user.save(function(err) {
                    if (err) {
                        throw err;
                    }

                    return done(null, user);
                });
            }


        });
    }));
};
