// !IMPORTS
// =============================================================================
// npm modules
var LocalStrategy    = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy  = require('passport-twitter').Strategy;
var GoogleStrategy   = require('passport-google-oauth').OAuth2Strategy;

// app modules
var config           = require('./index.js');
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
