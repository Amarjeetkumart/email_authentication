// middlewares/authMiddleware.js
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('../models/user');

//dotenv configuration
dotenv.config();
// Middleware to check if user is authenticated
const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token; 
  // Get token from cookies

  if (!token) {
    return res.redirect('/api/auth/login'); 
    // Redirect to login if no token is found
  }
  // Verify the token
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); 
    // Verify the token
    req.userId = decoded.id; 
    // Attach user ID to the request for use in other routes
    // Fetch the user's data from the database using the user ID
    const user = await User.findById(req.userId);
    if (!user) {
      return res.redirect('/api/auth/login');
    }
    // Redirect to login if user is not found
    req.user = user; 
    // Attach the user object to the request
    next(); 
    // Proceed to the next middleware or route handler
  } catch (error) {
    res.redirect('/api/auth/login'); 
    // Redirect to login if token verification fails
  }
};
// Export the middleware
module.exports = authMiddleware;
