const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bodyparser=require('body-parser')
require("dotenv").config();
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());
app.use(cors());

const connect = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Successfully db connected");
  } catch (error) {
    console.log(error);
  }
}

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});
const User = mongoose.model('User', userSchema);


app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({
      email,
      password: hashedPassword 
    });
     await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred on the server.' });
  }
});

// API for Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email credentials" });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid password credentials" });
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET);
    res.status(200).json({ token });
    
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "An error occurred while logging in" });
  }
});


const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.userId = decodedToken.userId;
    req.userEmail = decodedToken.email;
    next();
  });
};

app.get('/dashboard', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ email: user.email });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'An error occurred on the server.' });
  }
});

connect();
  app.listen(5000, () => console.log('Running on port 5000'));