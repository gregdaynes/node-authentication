// !IMPORTS
// =============================================================================
var LocalStrategy    = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy  = require('passport-twitter').Strategy;
var GoogleStrategy   = require('passport-google-oauth').OAuth2Strategy;
var config           = require('./index.js');
var User             = require('../app/models/user');


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





    // Facebook
    // ------------------------
    passport.use(new FacebookStrategy({

        // pull in app id and secret from config
        clientID: config.facebookAuth.clientID,
        clientSecret: config.facebookAuth.clientSecret,
        callbackURL: config.facebookAuth.callbackURL
    },

    // facebook will send back the token and profile
    function(token, refreshToken, profile, done) {

        // async
        process.nextTick(function() {

            // find the user in the database based on their facebook id
            User.findOne({ 'facebook.id': profile.id }, function(err, user) {
                // stop everything and return error
                if (err) {
                    return done(err);
                }

                // if user found, log them in
                if (user) {
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
        });
    }));





    // Twitter
    // ------------------------
    passport.use(new TwitterStrategy({

        // pull in app id and secret from config
        consumerKey: config.twitterAuth.consumerKey,
        consumerSecret: config.twitterAuth.consumerSecret,
        callbackURL: config.twitterAuth.callbaclURL
    },
    function(token, tokenSecret, profile, done) {

        // async
        // findOne will wait until we have all the data from twitter
        process.nextTick(function() {

            // try to find the user based on their twitter id
            User.findOne({ 'twitter.id': profile.id }, function(err, user) {

                // stop everything for errors
                if (err) {
                    return done(err);
                }

                // if user found, log them in
                if (user) {
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
        });
    }));





    // Google
    // ------------------------
    passport.use(new GoogleStrategy({

        // pull in app id and secret from config
        clientID: config.googleAuth.clientId,
        clientSecret: config.googleAuth.clientSecret,
        callbackURL: config.googleAuth.callbackURL
    },

    function(token, refreshToken, profile, done) {

        // async
        // findOne will wait until we have all the data from Google
        process.nextTick(function() {

            // try to find the user based on their google Id
            User.findOne({ 'google.id': profile.id }, function(err, user) {

                // stop everything for errors
                if (err) {
                    return done(err);
                }

                if (user) {

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
        });
    }));
};
