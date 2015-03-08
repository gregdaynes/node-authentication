// !IMPORTS
// =============================================================================
var express      = require('express');
var mongoose     = require('mongoose');
var passport     = require('passport');
var flash        = require('connect-flash');
var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var session      = require('express-session');
var ejs          = require('ejs');

// !MODULES
// =============================================================================
var app    = module.exports = express();
var config = require('./config');
  

// !CONFIG
// =============================================================================
mongoose.connect(config.db); // connect to database


// express middleware
app.use(morgan('dev')); // log every request to console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser.json()); // get information from html forms
app.use(bodyParser.urlencoded({extended: true }));

// app.set('views', __dirname + '/views'); // not needed if using /views
app.set('view engine', 'ejs'); // set ejs for templating

require('./config/passport')(passport); // passport 

// passport middleware
app.use(session({
    secret: config.secret  // session secret
  , resave: true
  , saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session


// !ROUTES
// =============================================================================
require('./app/routes.js')(app, passport); // load routes and pass in app and configured passport




