const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');
const cookieParser = require('cookie-parser');
// Load environment variables
dotenv.config();
// Create an Express app
const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Set view engine and middleware
app.use(express.json());
// express urlencoded middleware
app.use(express.urlencoded({ extended: false }));
// Set view engine and middleware
app.set('view engine', 'ejs');
app.set('views', './views');
// Set static folder
app.use(express.static('public'));
// Body parser middleware
app.use(bodyParser.json());
// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));
// Cookie parser middleware
app.use(cookieParser());
// Routes
app.use('/api/auth', authRoutes);

// Public routes
app.get('/', (req, res) => res.render('index'));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
