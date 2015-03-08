// !ROUTES
// =======

module.exports = function(app, passport) {

    // Home Page
    app.get('/', function(req, res) {
        res.render('index.ejs');
    });

    // login
    app.get('/login', function(req, res) {
        res.render('login.ejs', { message: req.flash('loginMessage' ) });
    });

    app.post('/login', passport.authenticate('local-login', {
        successRedirect: '/profile', // redirect to the secure profile
        failureRedirect: '/login', // back to login page if there is an error
        failurFlash: true // allow flash messages
    }));

    // signup
    app.get('/signup', function(req, res) {
        res.render('signup.ejs', { message: req.flash('signupMessage') });
    });

    // process signup form
    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect: '/profile', // redirect to the secure profile
        failureRedirect: '/signup', // redirect back to the signup page if there is an error
        failurFlash: true // allow flash message
    }));

    // profile
    app.get('/profile', isLoggedIn, function(req, res) {
        console.log('goto profile');
        res.render('profile.ejs', {
            user: req.user // get the user from a session
        });
    });

    // logout
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });
};

// check login middleware
function isLoggedIn(req, res, next) {
    
    if (req.isAuthenticated()) {
        return next();
    }

    // if they aren't
    res.redirect('/');
}
