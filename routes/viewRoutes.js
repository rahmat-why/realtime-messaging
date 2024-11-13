const express = require('express');
const cookieParser = require('cookie-parser');
const router = express.Router();
const jwt = require('jsonwebtoken');

router.use(cookieParser());

// JWT verification middleware
function verifyTokenView(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/view/login'); // Redirect to login page if no token
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token

        req.user = decoded; // Attach decoded payload to request
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        console.error('Invalid token:', error);
        return res.redirect('/view/login'); // Redirect to login if token is invalid
    }
}

// Route to render the Register view
router.get('/register', (req, res) => {
    res.render('register'); // This will render `views/register.ejs`
});

// Route to render the Login view
router.get('/login', (req, res) => {
    res.render('login'); // This will render `views/login.ejs`
});

// Route to render the Verify view
router.get('/verify', (req, res) => {
    const { status, message } = req.query; // Get `status` and `message` from req.query
    res.render('verify', { status, message }); // Pass them to the view
});

// Route to render the Verify Success view
router.get('/verify-success/:token', (req, res) => {
    res.render('verifySuccess'); // Renders `views/verify.ejs`
});

// Route to render the Mst User view
router.get('/user', verifyTokenView, (req, res) => {
    const user = req.user;
    if(user.role != 6) {
        return res.redirect('/view/message');
    }
    
    res.render('mstUser'); // Renders `views/mstUser.ejs`
});

// Route to render the Trx Message view
router.get('/message', verifyTokenView, (req, res) => {
    res.render('trxMessage'); // Renders `views/trxMessage.ejs`
});

module.exports = router;