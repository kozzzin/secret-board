const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  name: {
    type: String,
    required: [true, "You need the provide your name"],
  },
  surname: String,
  username: {
    type: String,
    required: [true, "You need the provide your username"],
    unique: true,
  },
  hash: {
    type: String,
    required: [true, "You need the provide your password"],
  },
  salt: {
    type: String,
    required: [true, "You need the provide salt for hash"],
  },
  isAdmin: {
    type: Boolean,
    required: [true, "You need the provide your surname"],
    default: false
  },
  isMember: {
    type: Boolean,
    required: [true, "You need the provide your surname"],
    default: false
  },
});

const User = mongoose.model('User', UserSchema);

module.exports = User;