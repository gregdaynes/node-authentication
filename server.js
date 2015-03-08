// !IMPORTS
// =============================================================================
var http = require('http');


// !MODULES
// =============================================================================
var app = require('./app.js');
var config = require('./config');
  

// !SERVER
// =============================================================================
http.createServer(app).listen(config.port, function() {
    console.log('Server is listening on port ' + config.port);
});
