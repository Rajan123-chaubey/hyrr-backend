const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');

const bodyParser = require('body-parser');

require('dotenv').config();

const app = express();
const { User, Post } = require('./db/db')

const PORT = 3001;
app.use(cors())

app.use(express.json());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));


app.post('/signup', async (req, res) => {
    try {
        const { email,username, password } = req.body;

        // Check if the username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user with the hashed password
        const newUser = new User({
            username,
            password: hashedPassword,
            email
        });

        // Save the user to the database
        await newUser.save();

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Error during user registration:', error);
        res.status(500).json({ message: 'Failed to register user' });
    }
});

app.post('/signin', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isPasswordValid = await user.isValidPassword(password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET,{expiresIn:"1h"});

        res.status(200).json({ token, message: 'Sign-in successful' });
    } catch (error) {
        console.error('Error during sign-in:', error);
        res.status(500).json({ message: 'Failed to sign in' });
    }
});

const authGuard = async (req, res, next) => {
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      try {
        const token = req.headers.authorization.split(" ")[1];
        const { id } = verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(id).select("-password");
        next();
      } catch (error) {
        let err = new Error("Not authorized, Token failed");
        err.statusCode = 401;
        next(err);
      }
    } else {
      let error = new Error("Not authorized, No token");
      error.statusCode = 401;
      next(error);
    }
  };
app.get('/posts',authGuard, async (req,res) => {
    try{
        const posts = await Post.find()

        res.json(posts)
    }
    catch (err){
        console.log("Error getting posts", err)

        res.status(500).json({message: "Failed to fetch posts"})
    }
    
})
app.get('/posts/:id', async (req, res) => {
    try {
        const postId = req.params.id;

        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }

        res.json(post);
    } catch (error) {
        console.error('Error getting post by ID:', error);
        res.status(500).json({ message: 'Failed to fetch post' });
    }
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

