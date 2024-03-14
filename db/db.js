const bcrypt = require('bcrypt');

const mongoose = require('mongoose');
require('dotenv').config();

const mongoURI = process.env.DB_URL

// Connect to MongoDB
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name:{ type: String},
  });

  userSchema.methods.isValidPassword = async function(password) {
    try {
        return await bcrypt.compare(password, this.password);
    } catch (error) {
        throw new Error(error);
    }
};

const postSchema = new mongoose.Schema({
    title:{
        type: String,
        required: true,
    },
    content:{
        type: String,
        required: true,
    },
    author:{
        type: String,
        required: true,
    },
    image:{
        type: String,
    },
    createdAt:{
        type: Date,
        default: Date.now
    }

})

const User = mongoose.model('User', userSchema)
const Post = mongoose.model('Post',postSchema)

module.exports = { User, Post};