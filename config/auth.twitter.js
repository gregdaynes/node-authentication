// !IMPORTS
// =============================================================================
// npm modules
var TwitterStrategy  = require('passport-twitter').Strategy;

// app modules
var config           = require('./index.js');
var User             = require('../app/models/user');


// expose this function to our app using exports
module.exports = function(passport) {

    // Twitter
    // ------------------------
    passport.use(new TwitterStrategy({

        // pull in app id and secret from config
        consumerKey: config.twitterAuth.consumerKey,
        consumerSecret: config.twitterAuth.consumerSecret,
        callbackURL: config.twitterAuth.callbackURL,
        passReqToCallback: true // allows us to pass the req from our route (lets us check if the user is logged in or not)
    },

    // twitter will send back the token and profile
    function(req, token, tokenSecret, profile, done) {

        // async
        // findOne will wait until we have all the data from twitter
        process.nextTick(function() {

            // check if user is already logged in
            if (!req.user) {

                // try to find the user based on their twitter id
                User.findOne({ 'twitter.id': profile.id }, function(err, user) {

                    // stop everything for errors
                    if (err) {
                        return done(err);
                    }

                    // if user found, log them in
                    if (user) {

                        // if there is a user id alreayd but no token
                        // add token and profile information
                        if (!user.twitter.token) {
                            user.twitter.token = token;
                            user.twitter.username = profile.username;
                            user.twitter.displayName = profile.displayName;

                            // save our user to the db
                            user.save(function(err) {
                                if (err) {
                                    throw err;
                                }
                                return done(null, user);
                            });
                        }

                        return done(null, user); // use user
                    }

                    // no user, create a new one
                    else {

                        var newUser = new User();

                        // set all the data that we will need
                        newUser.twitter.id = profile.id;
                        newUser.twitter.token = token;
                        newUser.twitter.username = profile.username;
                        newUser.twitter.displayName = profile.displayName;

                        // save our user into the database
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

                // update the current users profile credentials
                user.twitter.id = profile.id;
                user.twitter.token = token;
                user.twitter.username = profile.username;
                user.twitter.displayName = profile.displayName;

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
