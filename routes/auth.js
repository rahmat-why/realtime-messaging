const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sql = require('mssql');
const connectToDb = require('../config/db');

const router = express.Router();
const saltRounds = 10;
const nodemailer = require('nodemailer');

// Create a rate limit rule for login requests (5 requests per 1 minutes)
const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 10 minutes
    max: 5, // Limit each IP to 5 requests per window
    message: 'Too many login attempts, please try again later.',
    standardHeaders: true, // Return rate limit info in the response headers
    legacyHeaders: false, // Disable the X-RateLimit-* headers
    handler: (req, res) => {
        res.status(429).json({
            message: 'Too many login attempts, please try again later.'
        });
    }
});

// Create a rate limit rule for registration requests (5 requests per 1 minutes)
const registerLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 10 minutes
    max: 5, // Limit each IP to 5 requests per window
    message: 'Too many registration attempts, please try again later.',
    standardHeaders: true, // Return rate limit info in the response headers
    legacyHeaders: false, // Disable the X-RateLimit-* headers
    handler: (req, res) => {
        res.status(429).json({
            message: 'Too many registration attempts, please try again later.'
        });
    }
});

// Create a transporter object
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.MAILTRAP_USER,
        pass: process.env.MAILTRAP_PASS,
    },
    tls: {
        rejectUnauthorized: false // Accept self-signed certificates (for testing)
    }
});

const { io } = require('../server');

// JWT verification middleware
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Expecting 'Bearer <token>'

    if (!token) {
        return res.status(403).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token
        req.user = decoded; // Attach decoded payload to request
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        console.error('Invalid token:', error);
        return res.status(401).json({ message: 'Invalid token. Authorization denied.' });
    }
}

// User registration endpoint
router.post('/register', registerLimiter, async (req, res) => {
    const { username, password, email, role_id } = req.body;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const pool = await connectToDb();

    // Check if username or email already exists
    const existingUser = await pool.request()
        .input('username', sql.VarChar, username)
        .input('email', sql.VarChar, email)
        .query(`SELECT * FROM Users WHERE username = @username OR email = @email`);

    if (existingUser.recordset.length > 0) {
        return res.status(403).json({ message: 'Username or email is already registered.' });
    }

    const result = await pool.request()
        .input('username', sql.VarChar, username)
        .input('hashed_password', sql.VarChar, hashedPassword)
        .input('email', sql.VarChar, email)
        .input('role_id', sql.Int, role_id)
        .query(`INSERT INTO Users (username, hashed_password, email, role_id) 
            OUTPUT INSERTED.user_id 
            VALUES (@username, @hashed_password, @email, @role_id)`);

    const token = jwt.sign({ userId: result.recordset[0].user_id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    
    // Configure the mail options
    const mailOptions = {
        from: 'internetofgreen@gmail.com',
        to: email,
        subject: 'Login Verify',
        html: `Welcome ${username}, <br />Token to verify: <a href="http://localhost:5000/auth/verify/${token}">${token}</a>`
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
    
    res.status(201).json({ message: 'User registered successfully. Please verify your email', token: token });
});

// Verify email endpoint (assuming the link includes a verification token)
router.get('/verify/:token', async (req, res) => {
    try {
        const token = req.params.token;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log(decoded);
        
        const pool = await connectToDb();

        await pool.request()
            .input('user_id', sql.Int, decoded.userId)
            .query('UPDATE Users SET is_email_verified = 1 WHERE user_id = @user_id');
        
        res.redirect(`/view/verify-success/${token}`);
    } catch (error) {
        const status = "Token invalid!"
        const message = "Please check your email then verify the valid token!";
        res.render('verify', { status, message }); // Pass them to the view
    }
});

// Login route
router.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    try {
        // Connect to the database
        const pool = await connectToDb();

        // Fetch the user record from the database
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM Users WHERE username = @username');

        // Check if user exists
        if (result.recordset.length === 0) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const user = result.recordset[0];

        // Check if the password matches
        const isPasswordValid = await bcrypt.compare(password, user.hashed_password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Check if email is verified
        if (!user.is_email_verified){
            return res.status(403).json({ message: 'Email not verified. Please verify your email before logging in.' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.user_id, 
                role: user.role_id, 
                emailVerified: user.is_email_verified 
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expiration time
        );
        
        // Configure the mail options
        const mailOptions = {
            from: 'internetofgreen@gmail.com',
            to: user.email,
            subject: 'Login Verify',
            html: `Welcome ${user.username}, <br />Token to verify: <a href="http://localhost:5000/auth/verify/${token}">${token}</a>`
        };

        // Send the email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
            } else {
                console.log('Email sent:', info.response);
            }
        });
        
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// GET /me route to get logged-in user's details
router.get('/me', verifyToken, async (req, res) => {
    try {
        const { userId } = req.user; // userId is decoded from the JWT

        // Connect to the database
        const pool = await connectToDb();

        // Fetch the user details
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .query(
                `SELECT 
                    u.username, 
                    u.email, 
                    u.role_id, 
                    r.role_name, 
                    u.is_email_verified 
                FROM 
                    Users u
                JOIN 
                    Role r ON u.role_id = r.role_id
                WHERE 
                    u.user_id = @userId`
            );

        if (result.recordset.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = result.recordset[0];

        // Return user data
        res.status(200).json(user);
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete User route (soft delete by setting is_email_verified to -1)
router.delete('/delete/:userId',verifyToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        // Connect to the database
        const pool = await connectToDb();

        // Update the user's is_email_verified status to 0
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .query('UPDATE Users SET is_email_verified = 0 WHERE user_id = @userId');

        // Check if any row was affected (user existed)
        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'User deleted successfully.' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Activate User route
router.put('/activate/:userId',verifyToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        // Connect to the database
        const pool = await connectToDb();

        // Update the user's is_email_verified status to 0
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .query('UPDATE Users SET is_email_verified = 1 WHERE user_id = @userId');

        // Check if any row was affected (user existed)
        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'User activated successfully.' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get All Users route
router.get('/users', verifyToken, async (req, res) => {
    try {
        // Connect to the database
        const pool = await connectToDb();

        // Query to select all users who are not marked as deleted
        const result = await pool.request()
        .query(`
            SELECT u.user_id, u.username, u.email, u.role_id, r.role_name, u.is_email_verified 
            FROM Users u
            INNER JOIN Role r ON u.role_id = r.role_id
        `);

        res.status(200).json(result.recordset);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get All Users route
router.get('/chat-users', verifyToken, async (req, res) => {
    const sender_id = req.user.userId; // Extract sender_id from the JWT token
    try {
        // Connect to the database
        const pool = await connectToDb();

        // Query to select all users who are not marked as deleted
        const result = await pool.request()
        .input('sender', sql.Int, sender_id)
        .query(`
            SELECT u.user_id, u.username, u.email, u.role_id, r.role_name, u.is_email_verified 
            FROM Users u
            INNER JOIN Role r ON u.role_id = r.role_id
            WHERE u.is_email_verified = 1 AND u.user_id != @sender
        `);

        res.status(200).json(result.recordset);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update User route
router.put('/update/:userId', verifyToken, async (req, res) => {
    const { userId } = req.params;
    const { email, role_id, password } = req.body;

    try {
        // Connect to the database
        const pool = await connectToDb();

        // Prepare the fields to update
        const updateFields = [];
        if (email) updateFields.push(`email = @newEmail`);
        if (role_id !== undefined) updateFields.push(`role_id = @newRoleId`);

        // Hash the password if it's provided
        let hashedPassword;
        if (password) {
            hashedPassword = await bcrypt.hash(password, saltRounds);
            updateFields.push(`hashed_password = @newPassword`);
        }

        // Construct the update query dynamically based on the fields provided
        const query = `UPDATE Users SET ${updateFields.join(', ')} WHERE user_id = @userId`;

        // Set up the SQL request and input the values if they're provided
        const request = pool.request().input('userId', sql.Int, userId);
        if (email) request.input('newEmail', sql.VarChar, email);
        if (role_id !== undefined) request.input('newRoleId', sql.Int, role_id);
        if (hashedPassword) request.input('newPassword', sql.VarChar, hashedPassword);

        // Execute the query
        const result = await request.query(query);

        // Check if the user was updated
        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ message: 'User not found or no changes made' });
        }

        res.status(200).json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create User route
router.post('/create', verifyToken, async (req, res) => {
    const { username, password, email, role_id } = req.body;

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Connect to the database
        const pool = await connectToDb();

        // Check if username or email already exists
        const existingUser = await pool.request()
            .input('username', sql.VarChar, username)
            .input('email', sql.VarChar, email)
            .query(`SELECT * FROM Users WHERE username = @username OR email = @email`);

        if (existingUser.recordset.length > 0) {
            return res.status(403).json({ message: 'Username or email is already registered.' });
        }

        // Insert the new user, setting is_email_verified to 1
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .input('hashed_password', sql.VarChar, hashedPassword)
            .input('email', sql.VarChar, email)
            .input('role_id', sql.Int, role_id)
            .query(`
                INSERT INTO Users (username, hashed_password, email, role_id, is_email_verified) 
                VALUES (@username, @hashed_password, @email, @role_id, 1)
            `);

        res.status(201).json({ message: 'User created and activated successfully.' });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Message creation route
router.post('/send-message', verifyToken, async (req, res) => {
    const { receiver_id, content } = req.body;
    const sender_id = req.user.userId; // Extract sender_id from the JWT token

    if (!Array.isArray(receiver_id) || receiver_id.length === 0 || !content) {
        return res.status(400).json({ message: 'Receiver IDs and message content are required' });
    }

    try {
        const pool = await connectToDb();

        // Convert receiver_id array to a JSON string to store in the database
        const receiverIdJson = JSON.stringify(receiver_id);

        // Insert message with encoded receiver_id array
        await pool.request()
            .input('sender_id', sql.Int, sender_id)
            .input('receiver_id', sql.VarChar, receiverIdJson)
            .input('content', sql.Text, content)
            .query(`
                INSERT INTO Messages (sender_id, receiver_id, content) 
                VALUES (@sender_id, @receiver_id, @content)
            `);

        res.status(201).json({ message: 'Message sent successfully.' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Server error while sending the message.' });
    }
});

// Receive messages route
router.get('/receive-message', verifyToken, async (req, res) => {
    const {userId,role} = req.user;

    try {
        const pool = await connectToDb();

        // normal user
        if(role == 4) {
            var result = await pool.request()
                .input('userId', sql.Int, userId)
                .query(`
                    SELECT message_id, sender_id, Users.username as sender_name, receiver_id, content, timestamp
                    FROM Messages 
                    JOIN Users ON Users.user_id = Messages.sender_id
                    WHERE message_id IN (
                        SELECT message_id
                        FROM Messages 
                        OUTER APPLY OPENJSON(receiver_id) 
                            WITH (userId INT '$.userId') AS jsonReceiver
                        WHERE jsonReceiver.userId = @userId OR sender_id = @userId
                    )
                    ORDER BY timestamp DESC;
                `);
        }else{
            var result = await pool.request()
                .query(`
                    SELECT message_id, sender_id, Users.username as sender_name, receiver_id, content, timestamp
                    FROM Messages 
                    JOIN Users ON Users.user_id = Messages.sender_id
                    WHERE message_id IN (
                        SELECT message_id
                        FROM Messages 
                        OUTER APPLY OPENJSON(receiver_id) 
                            WITH (userId INT '$.userId') AS jsonReceiver
                    )
                    ORDER BY timestamp DESC;
                `);
        }

        // If no messages found, return empty array
        if (result.recordset.length === 0) {
            return res.status(200).json({ messages: [] });
        }

        // Map over the results and add the 'type' attribute
        const messagesWithType = result.recordset.map(message => {
            const type = message.sender_id === userId ? 'out' : 'in';
            return { ...message, type };
        });

        // Return the list of messages with the type attribute
        res.status(200).json({ messages: messagesWithType });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ message: 'Server error while fetching messages.' });
    }
});

// Get All Roles route
router.get('/roles', async (req, res) => {
    try {
        // Connect to the database
        const pool = await connectToDb();

        // Query to select all roles
        const result = await pool.request()
            .query('SELECT role_id, role_name FROM Role');

        res.status(200).json(result.recordset);
    } catch (error) {
        console.error('Error retrieving roles:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;