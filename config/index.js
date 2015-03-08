module.exports = {
    'port': process.env.PORT || 8080
  , 'db': 'mongodb://localhost:27017/db_node-auth'
  , 'secret': 'supersecret' // token secret
}