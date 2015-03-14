// !IMPORTS
// =============================================================================
// npm modules
var FacebookStrategy = require('passport-facebook').Strategy;

// app modules
var config           = require('./index.js');
var User             = require('../app/models/user');


// expose this function to our app using exports
module.exports = function(passport) {

    // Facebook
    // ------------------------
    passport.use(new FacebookStrategy({

        // pull in app id and secret from config
        clientID: config.facebookAuth.clientID,
        clientSecret: config.facebookAuth.clientSecret,
        callbackURL: config.facebookAuth.callbackURL,
        passReqToCallback: true // allows us to pass in the req from our route (lets us check if user is logged in or not)
    },

    // facebook will send back the token and profile
    function(req, token, refreshToken, profile, done) {

        // async
        process.nextTick(function() {

            // check if user is already logged in
            if (!req.user) {

                // find the user in the database based on their facebook id
                User.findOne({ 'facebook.id': profile.id }, function(err, user) {

                    // stop everything and return error
                    if (err) {
                        return done(err);
                    }

                    // if user found, log them in
                    if (user) {

                        // if there is a user id already but no token (user was linked and then removed)
                        // add our token and profile information
                        if (!user.facebook.token) {
                            user.facebook.token = token;
                            user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                            user.facebook.email = profile.emails[0].value;

                            user.save(function(err) {
                                if (err) {
                                    throw err;
                                }

                                return done(null, user);
                            });
                        }

                        return done(null, user); // user found, use user
                    }

                    // no user with facebook id - create one
                    else {

                        var newUser = new User();

                        // set all of the facebook information in our user model
                        newUser.facebook.id = profile.id; // sets the users facebook id
                        newUser.facebook.token = token; // we will save the token facebook provides for the user
                        newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how names are returned
                        newUser.facebook.email = profile.emails[0].value; // facebook can return multiple emails, we'll use the first

                        // save new user to db
                        newUser.save(function(err) {
                            if (err) {
                                throw err;
                            }

                            // if successful, return new user
                            return done(null, newUser);
                        });
                    }
                });
            }

            // user already exists and is logged in
            // lets link the accounts
            else {

                var user = req.user; // pull the user out of the session

                // update the current users facebook credentials
                user.facebook.id = profile.id;
                user.facebook.token = token;
                user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                user.facebook.email = profile.emails[0].value;

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
