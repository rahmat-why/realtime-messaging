const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sql = require('mssql');
const connectToDb = require('../config/db');

const router = express.Router();
const saltRounds = 10;

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
router.post('/register', async (req, res) => {
    const { username, password, email, role_id } = req.body;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const pool = await connectToDb();
    const result = await pool.request()
        .input('username', sql.VarChar, username)
        .input('hashed_password', sql.VarChar, hashedPassword)
        .input('email', sql.VarChar, email)
        .input('role_id', sql.Int, role_id)
        .query(`INSERT INTO Users (username, hashed_password, email, role_id) 
            OUTPUT INSERTED.user_id 
            VALUES (@username, @hashed_password, @email, @role_id)`);

    const verificationToken = jwt.sign({ userId: result.recordset[0].user_id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    
    res.status(201).json({ message: 'User registered successfully. Please verify your email', token: verificationToken });
});

// Verify email endpoint (assuming the link includes a verification token)
router.get('/verify/:token', async (req, res) => {
    try {
        const token = req.params.token;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const pool = await connectToDb();
        await pool.request()
            .input('user_id', sql.Int, decoded.userId)
            .query('UPDATE Users SET is_email_verified = 1 WHERE user_id = @user_id');
        
        res.json({ message: 'Email verified successfully.' });
    } catch (error) {
        res.status(400).json({ error: 'Invalid or expired token.' });
    }
});

// Login route
router.post('/login', async (req, res) => {
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

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete User route (soft delete by setting is_email_verified to -1)
router.delete('/delete/:userId',verifyToken, async (req, res) => {
    const userId = req.params.userId;

    console.log(userId);

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

        res.status(200).json({ message: 'User has been marked as deleted' });
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
            .query('SELECT user_id, username, email, role_id, is_email_verified FROM Users WHERE is_email_verified != 0');

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

        res.status(201).json({ message: 'User created successfully and is_email_verified set to 1.' });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Message creation route
router.post('/send-message', verifyToken, async (req, res) => {
    const { receiver_id, content } = req.body;
    const sender_id = req.user.userId; // Extract sender_id from the JWT token

    if (!receiver_id || !content) {
        return res.status(400).json({ message: 'Receiver ID and message content are required' });
    }

    try {
        const pool = await connectToDb();

        // Insert message into the database
        // const result = await pool.request()
        //     .input('sender_id', sql.Int, sender_id)
        //     .input('receiver_id', sql.Int, receiver_id)
        //     .input('content', sql.Text, content)
        //     .query(`
        //         INSERT INTO Messages (sender_id, receiver_id, content) 
        //         VALUES (@sender_id, @receiver_id, @content)
        //     `);

        req.io.emit('sendMessage', {
            sender_id: sender_id,
            content: content,
            timestamp: new Date()
        });

        res.status(201).json({ message: 'Message sent successfully.' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Server error while sending the message.' });
    }
});

// Receive messages route
router.get('/receive-message', verifyToken, async (req, res) => {
    const userId = req.user.userId;

    try {
        const pool = await connectToDb();

        // Query to fetch all messages where receiver_id matches or sender_id matches
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .query(`
                SELECT message_id, sender_id, receiver_id, content, timestamp 
                FROM Messages 
                WHERE receiver_id = @userId OR sender_id = @userId
                ORDER BY timestamp DESC
            `);

        // If no messages found, return empty array
        if (result.recordset.length === 0) {
            return res.status(200).json({ messages: [] });
        }

        // Map over the results and add the 'type' attribute
        const messagesWithType = result.recordset.map(message => {
            const type = message.receiver_id === userId ? 'in' : 'out';
            return { ...message, type };
        });

        // Return the list of messages with the type attribute
        res.status(200).json({ messages: messagesWithType });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ message: 'Server error while fetching messages.' });
    }
});

module.exports = router;