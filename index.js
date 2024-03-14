const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
var cookieParser = require('cookie-parser')

const bodyParser = require('body-parser');

require('dotenv').config();

const app = express();
const { User, Post } = require('./db/db')

const PORT = 3001;
app.use(cors())
app.use(cookieParser());

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
        const newUser = await User.create({
            username,
            password: hashedPassword,
            email
        });

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Error during user registration:', error);
        res.status(500).json({ message: 'Failed to register user' });
    }
});

app.post('/signin', async (req, res) => {
    try {
        const { username, password } = req.body;

        const existingUser = await User.findOne({ username });

        if (!existingUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isPasswordValid = await existingUser.isValidPassword(password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        // const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET,{expiresIn:"1h"});
        const jwtToken = jwt.sign(
            {
              _id: existingUser._id,
              username: existingUser.username,
            },
            process.env.JWT_SECRET
          );
      
          res.cookie("token", jwtToken, {
            path: "/",
            expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
            httpOnly: true,
            sameSite: "lax",
          });
      

        res.status(200).json({jwtToken, message: 'Sign-in successful' });
    } catch (error) {
        console.error('Error during sign-in:', error);
        res.status(500).json({ message: 'Failed to sign in' });
    }
});

app.post("/logout", async (req, res) => {
    try {
      res.clearCookie("token");
      return res.status(200).send({ message: "logged out successfully!" });
    } catch (error) {
      return res.status(500).send({ message: "Error logging out!", error });
    }
  });

// const authGuard = async (req, res, next) => {
//     if (
//       req.headers.authorization &&
//       req.headers.authorization.startsWith("Bearer")
//     ) {
//       try {
//         const token = req.headers.authorization.split(" ")[1];
//         const { id } = verify(token, process.env.JWT_SECRET);
//         req.user = await User.findById(id).select("-password");
//         next();
//       } catch (error) {
//         let err = new Error("Not authorized, Token failed");
//         err.statusCode = 401;
//         next(err);
//       }
//     } else {
//       let error = new Error("Not authorized, No token");
//       error.statusCode = 401;
//       next(error);
//     }
//   };

const authGuard = async (req, res, next) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            throw new Error("Not authorized, No token");
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded._id).select("-password");
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(401).json({ message: error.message || 'Not authorized' });
    }
};


app.get('/posts',authGuard, async (req,res) => {
    try{
        const posts = await Post.find();
        res.json(posts)
    }
    catch (err){
        console.log("Error getting posts", err)

        res.status(500).json({message: "Failed to fetch posts"})
    }
    
})
app.get('/posts/:id', authGuard, async (req, res) => {
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

