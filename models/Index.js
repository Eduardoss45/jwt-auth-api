const mongoose = require("mongoose");

// * modelos
const User = mongoose.model('User', {
    name: String,
    email: String,
    password: String
})

// * exportando modelos
module.exports = { User };