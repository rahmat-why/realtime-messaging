const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const connectToDb = require('./config/db');
const authRoutes = require('./routes/auth');
const viewRoutes = require('./routes/viewRoutes');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.json());

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on("socket-send-message", message => {
        socket.broadcast.emit("socket-receive-message");
    });

    // Disconnect event
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

app.use('/auth', authRoutes);
app.use('/view', viewRoutes);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

server.listen(5000, () => console.log('Server running on port 5000'));

module.exports = io;