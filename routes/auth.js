const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const sendEmail = require('../utils/sendEmail');
const dotenv = require('dotenv');
const authMiddleware = require('../middlewares/authMiddleware');
// Load environment variables
dotenv.config();
// Create a new router
const router = express.Router();

// Apply authMiddleware to the dashboard get route
router.get('/dashboard', authMiddleware, (req, res) => {
  res.render('dashboard', { username: req.user.username }); 
  // Render dashboard if authenticated
});
// Logout get route
router.get('/logout', (req, res) => {
  res.clearCookie('token'); 
  // Clear the cookie with the name 'token'
  res.redirect('/api/auth/login'); 
  // Redirect user to the login page after logout
});


// Display registration page
router.get('/register', (req, res) => {
  res.render('register');
});

// Display login page
router.get('/login', (req, res) => {
  res.render('login', { message: '', error: '' });
});

// Registration route
router.post('/register', async (req, res) => {
  // Implement registration logic here
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create a new user
    const user = new User({ username, email, password: hashedPassword });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    user.emailVerificationToken = token;
    await user.save();
    // Send verification email
    const verificationUrl = `http://localhost:3000/api/auth/verify-email/${token}`;
    await sendEmail(email, 'Verify Your Email', `Please verify your email by clicking on this link: ${verificationUrl}`);
    // Redirect to login page
    res.render('login', { message: 'Registration successful! Please verify your email to log in.', error: '' });
  } catch (error) {
    res.render('register', { error: 'Error during registration. Please try again.' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  // Implement login logic here
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    // Check if user exists and password is correct
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { message: '', error: 'Invalid credentials' });
    }
    if (!user.isVerified) {
      return res.render('login', { message: '', error: 'Please verify your email before logging in' });
    }
    //chatGpt
    // generate a token for the user
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Set JWT token in an HTTP-only cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000,
    });
    //end chatGpt
    res.redirect('/api/auth/dashboard');
  } catch (error) {
    res.render('login', { message: '', error: 'An error occurred during login. Please try again.' });
  }
});

// Email verification route
router.get('/verify-email/:token', async (req, res) => {
  // Implement email verification logic here
  try {
    const decoded = jwt.verify(req.params.token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    // Check if user exists and is not verified
    if (!user) {
      return res.render('login', { message: '', error: 'Invalid or expired verification link' });
    }
    // Verify the user
    user.isVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();
    // Redirect to login page
    res.render('login', { message: 'Email verified! You can now log in.', error: '' });
  } catch (error) {
    res.render('login', { message: '', error: 'Verification link is invalid or has expired.' });
  }
});

// Forgot password route
router.post('/forgot-password', async (req, res) => {
  // Implement forgot password logic here
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    // Check if user exists
    if (!user) {
      return res.render('forgot-password', { message: "", error: 'No user found with this email.' });
    }
    // Generate password reset token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    user.passwordResetToken = token;
    user.passwordResetExpires = Date.now() + 15 * 60 * 1000;
    await user.save();
    // Send password reset email
    const resetUrl = `http://localhost:3000/api/auth/reset-password/${token}`;
    await sendEmail(email, 'Password Reset', `Reset your password by clicking this link: ${resetUrl}`);
    // Redirect to login page
    res.render('login', { message: 'Password reset email sent! Please check your inbox.', error: '' });
  } catch (error) {
    res.render('forgot-password', { error: 'An error occurred. Please try again later.' });
  }
});

// Reset password route
router.post('/reset-password/:token', async (req, res) => {
  // Implement reset password logic here
  try {
    const user = await User.findOne({
      passwordResetToken: req.params.token,
      passwordResetExpires: { $gt: Date.now() },
    });
    // Check if user exists and token is valid
    if (!user) {
      return res.render('reset-password', { error: 'Invalid or expired token' });
    }
    // Update user's password
    user.password = await bcrypt.hash(req.body.password, 10);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    // Redirect to login page
    res.render('login', { message: 'Password reset successful! You can now log in.', error: '' });
  } catch (error) {
    res.render('reset-password', { error: 'An error occurred during password reset. Please try again.' });
  }
});

//get route for forgot password
router.get('/forgot-password', (req, res) => {
  res.render('forgot-password' , { message: " ", error: " " });
});

//get route for reset password
router.get('/reset-password/:token', (req, res) => {
  res.render('reset-password', { message: " ", error: " ",token: req.params.token });
});
// Export the router
module.exports = router;
