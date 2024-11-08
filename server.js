const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const connectToDb = require('./config/db');
const authRoutes = require('./routes/auth');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());

// Pass io to auth routes
app.use('/auth', (req, res, next) => {
    req.io = io;
    next();
}, authRoutes);

// Authenticate Socket.io connections
io.use((socket, next) => {
    console.log(1);
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error("Authentication error"));
    }

    console.log(2);
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return next(new Error("Authentication error"));
        }
        socket.user = decoded;
        next();
    });

    console.log(3);
});

// Handle messaging
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.user.username}`);
});

server.listen(5000, () => console.log('Server running on port 5000'));