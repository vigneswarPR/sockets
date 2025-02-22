const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);
const crypto = require('crypto'); // For generating random room IDs

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/basicsocket.html');
});

const rooms = {}; // Store rooms and their connected sockets

io.on('connection', (socket) => {
    console.log('a user connected:', socket.id);

    socket.on('create_room', (callback) => {
        let roomId;
        do {
            roomId = generateRoomId(); // Generate room ID
        } while (rooms[roomId]); // Ensure the ID is unique

        rooms[roomId] = { sockets: [socket] }; // Create the room and add the creator
        socket.join(roomId); // Join the creator to the room
        callback(roomId); // Send the room ID back to the client
        socket.emit('user_joined', roomId, socket.id); // Notify the creator they joined
        console.log(`Room created: ${roomId}`);
    });

    socket.on('join_room', (roomId, callback) => {
        if (rooms[roomId]) { // Check if the room exists
            socket.join(roomId);
            rooms[roomId].sockets.push(socket); // Add the user to the room
            callback(true); // Signal success to the client
            io.to(roomId).emit('user_joined', roomId, socket.id); // Notify all in the room
            console.log(`User ${socket.id} joined room ${roomId}`);
        } else {
            callback(false); // Signal failure (room doesn't exist)
        }
    });


    socket.on('chat message', (data) => {
        io.to(data.room).emit('chat message', data); // Send to the specific room
    });

    socket.on('disconnect', () => {
        console.log('user disconnected:', socket.id);
        for (const roomId in rooms) {
            if (rooms[roomId].sockets) {
                rooms[roomId].sockets = rooms[roomId].sockets.filter(s => s !== socket);
                if (rooms[roomId].sockets.length === 0) {
                    delete rooms[roomId];
                    console.log(`Room ${roomId} deleted as it has no users`);
                } else {
                    io.to(roomId).emit('user_left', roomId, socket.id); // Notify other users
                }
            }
        }
    });

    socket.on('leave_room', (roomId) => {
        socket.leave(roomId);
        if (rooms[roomId] && rooms[roomId].sockets) {
            rooms[roomId].sockets = rooms[roomId].sockets.filter(s => s !== socket);
            if (rooms[roomId].sockets.length === 0) {
                delete rooms[roomId];
                console.log(`Room ${roomId} deleted as it has no users`);
            } else {
                io.to(roomId).emit('user_left', roomId, socket.id); // Notify other users
            }
        }
    });

});


function generateRoomId() {
    return crypto.randomBytes(6).toString('hex').toUpperCase(); // Generate a random ID
}

server.listen(4000, () => {
    console.log('listening on *:4000');
});