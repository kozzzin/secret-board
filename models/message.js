const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const MessageSchema = new Schema({
  title: {
    type: String,
    required: [true, 'You have to provide title for messaage']
  },
  text: {
    type: String,
    required: [true, 'You have to provide text for messaage']
  },
  date: {
    type: Date,
    default: Date.now
  },
  author: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  }
});
// 
// CategorySchema.virtual('url').get(function() {
//   return `/category/${this._id}`;
// });

const Message = mongoose.model("Message", MessageSchema);


module.exports = Message;
