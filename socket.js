const express = require('express');
const uri = "mongodb+srv://system:system@viki.umvya.mongodb.net/auth";
const app = express();
const cloudinary = require('cloudinary').v2;
const crypt = require('./msgcrypt');




cloudinary.config({
    cloud_name: 'dojxw2gy6',
    api_key: '456888777672528',
    api_secret: 'TtcgMkPcl_iAWPGXi7jtwqcxb5A' // Click 'View API Keys' above to copy your API secret
});
const jwt = require('jsonwebtoken');
const SymSpell = require('node-symspell');
const maxEditDistance = 2;
const prefixLength = 7;
const symSpell = new SymSpell(maxEditDistance, prefixLength);
(async () => {
    await symSpell.loadDictionary('./freq_dict.txt', 0, 1);
    await symSpell.loadBigramDictionary('./bigram.txt', 0, 2);
})();
const bcrypt = require('bcrypt');
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);
const session = require('express-session');
const mailer = require('nodemailer');
const cors = require('cors');
const passport = require('passport');
const googlestrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const mongoose = require('mongoose');
mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000, // Increase connection timeout if needed
    bufferTimeoutMS: 30000 // Increase query timeout (30 seconds)
})
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB connection error:", err));

app.use(cors()); // Enable CORS for all origins (or configure as needed)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration (before passport middleware)
app.use(
    session({
        secret: 'your_secret_key', // CHANGE THIS TO A RANDOM, STRONG SECRET!
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false, // Set to true if using HTTPS in production
            httpOnly: true, // Essential for security
            maxAge: 3600000 // 1 hour
        },
    })
);

app.use(passport.initialize());
app.use(passport.session()); // Place after session middleware


// MongoDB connection
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB connection error:", err));

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: false }
});
const historySchema = new mongoose.Schema({
    email: { type: String, required: true, unique: false },
    chathistory: { type: String, required: true },
    key: { type: String, required: true },
    iv: { type: String, required: true },
    hroomid: { type: String, required: false }
});
const history = mongoose.model('newchathistory', historySchema);

const User = mongoose.model('socket', UserSchema);

// Google OAuth Strategy
passport.use(new googlestrategy({
    clientID: '927044143615-mmi8f7vdh8k4r1ijsjec3fdk3o67pqb9.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: 'http://localhost:4000/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
    // Check if the user exists in your database
    User.findOne({ email: profile.emails[0].value })
        .then(user => {
            if (user) {
                return done(null, user); // User exists, return the user
            } else {
                // User doesn't exist, create a new user and return it
                const newUser = new User({
                    email: profile.emails[0].value
                });
                newUser.save()
                    .then(user => done(null, user))
                    .catch(err => console.error(err));
            }
        });
}));

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/intro.html');
});
app.get('/loginpage', (req, res) => {
    res.sendFile(__dirname + '/login.html');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        req.session.username = req.user.email; // Set username in session after Google login
        res.redirect('/home');
    });
app.post('/log', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email });
    const token = jwt.sign(
        { userId: user._id, email: user.email },
        'cat',
        { expiresIn: '1h' }
    );
    req.session.jwttoken = token;



    if (!user) {
        return res.redirect('/signup');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ message: 'invalid credentials' });
    }

    req.session.username = user.email;
    console.log(req.session.username); // Store username in session
    return res.redirect('/verify');
});

app.get('/api/username', (req, res) => {
    if (req.session.username) {
        res.json({ username: req.session.username });
    } else {
        res.status(401).json({ message: "Unauthorized" });
    }
});
app.get('/msg/username', (req, res) => {
    if (req.session.username) {
        res.json({ username: req.session.username });
    } else {
        res.status(401).json({ message: "Unauthorized" });
    }
});
app.get('/resetpwd', (req, res) => {
    res.sendFile(__dirname + '/resetpwd.html');
});
function verifyToken(req, res, next) {
    const token = req.session.jwttoken; // Retrieve token from session

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, 'cat', (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Failed to authenticate token' });
        }

        req.userId = decoded.userId; // Store decoded user ID in request
        next();
    });
}



app.get('/home', verifyToken, (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/signup.html');
});



app.get('/verify', (req, res) => {
    res.sendFile(__dirname + '/verify.html');
});
app.post('/otp', async (req, res) => {

    const mail = req.body.email;
    res.sendFile(__dirname + '/otp.html');
    try {
        const u = await User.findOne({ email: mail });
        if (!u) {
            return res.status(400).json({ message: 'User not found' });
        }

        const token = Math.random().toString(36).slice(-8);
        req.session.token = token;

        const transporter = mailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'vikiinfinity2005@gmail.com',
                pass: 'aoym sqoy zgcv ohvu'
            }
        });

        const mess = {
            from: "vikiinfinity2005@gmail.com",
            to: u.email, // Use u.email
            subject: "Password Reset",
            text: `Use the following token to reset password: ${token}`
        };

        await transporter.sendMail(mess);







    } catch (error) {
        console.error("Error sending email:", error);
        res.status(500).json({ message: 'Failed to send email' }); // Send error response
    }
});
app.post('/repwd', (req, res) => {
    const token = req.body.token;
    if (token == req.session.token) {
        res.sendFile(__dirname + '/newpwd.html');
    }
});
app.post('/newpwdcreated', async (req, res) => {
    const newpassword = req.body.password;
    const confirmpassword = req.body.confirmpassword;
    if (newpassword !== confirmpassword) {
        return res.status(400).json({ message: 'passwords do not match' });
    }
    res.redirect('/home');


    const sr = 10;
    const sal = await bcrypt.genSaltSync(sr);
    const shashedpassword = await bcrypt.hash(newpassword, sal);

    await User.updateOne({ email: req.session.username }, { password: shashedpassword });


});
app.post('/l', async (req, res) => {

    const semail = req.body.email;
    const spassword = req.body.password;
    const confirmpassword = req.body.cp;

    if (spassword !== confirmpassword) {
        return res.status(400).json({ message: 'passwords do not match' });
    }

    const sr = 10;
    const sal = await bcrypt.genSaltSync(sr);
    const shashedpassword = await bcrypt.hash(spassword, sal);

    const snew = new User({ email: semail, password: shashedpassword });
    await snew.save();


});

let rooms = {};
let historyrooms = {};
// Socket.IO
io.on('connection', (socket) => {
    console.log('a user connected:', socket.id);

    socket.on('create_room', (callback) => {
        let roomId;
        do {
            roomId = generateRoomId();
            //historyrooms.push(roomId);
        } while (rooms[roomId]);

        rooms[roomId] = { sockets: [socket] };
        socket.join(roomId);
        callback(roomId);
        socket.emit('user_joined', roomId, socket.id);
        console.log(`Room created: ${roomId}`);
    });

    socket.on('join_room', async (roomId, callback) => {
        try {
            const findroom = await history.find({ hroomid: roomId });

            if (findroom && findroom.length > 0) {
                socket.join(roomId); //Join the room


                console.log(`User ${socket.id} joined room ${roomId}`); // Check if findroom has results
                findroom.forEach((doc) => {
                    console.log('document', doc);
                    const k = doc.key;
                    const i = doc.iv;
                    const deckey = crypt.base64ToKey(k);
                    const deciv = crypt.base64ToIV(i);
                    const decmsg = crypt.decrypt(doc.chathistory, deckey, deciv);
                    console.log(decmsg);
                    io.to(roomId).emit('chat message', { username: doc.email, msg: decmsg, room: doc.hroomid });
                });
                callback(true);
                io.to(roomId).emit('user_joined', roomId, socket.id);



            } else {
                if (rooms[roomId]) {
                    rooms[roomId].sockets.push(socket);
                    socket.join(roomId);
                    callback(true);
                    io.to(roomId).emit('user_joined', roomId, socket.id);
                    console.log(`User ${socket.id} joined room ${roomId}`);
                } else {
                    callback(false); // Indicate failure
                }

            }
        } catch (error) {
            console.error('Error joining room:', error);
            callback(false); // Indicate failure due to an error
        }
    });
    socket.on('uploadimage', (data) => {
        console.log({ data });


        const response = cloudinary.uploader.upload(data.image, {


            folder: 'chat-images'

        })
            .then((response) => {
                const downloadUrl = response.secure_url.replace('/upload/', '/upload/fl_attachment/');


                io.to(data.room).emit('image', data.image, downloadUrl);
                console.log(response.secure_url);
                console.log(` ${data.username} uploaded image in room ${data.room}`);
            });



    });

    socket.on('chat message', (data) => {
        const correctedMessage = symSpell.lookupCompound(data.msg, maxEditDistance)[0].term;
        console.log(correctedMessage);
        const { key, iv } = crypt.generateKeyAndIV();
        const keyBase64 = crypt.keyToBase64(key);
        const ivBase64 = crypt.ivToBase64(iv);
        io.to(data.room).emit('chat message', data);
        const enc = crypt.encrypt(data.msg, key, iv);
        const newhistory = new history({ email: data.username, chathistory: enc, hroomid: data.room, key: keyBase64, iv: ivBase64 });
        newhistory.save();
        console.log(data);
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
                    io.to(roomId).emit('user_left', roomId, socket.id);
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
                io.to(roomId).emit('user_left', roomId, socket.id);
            }
        }
    });
});

function generateRoomId() {
    return crypto.randomBytes(6).toString('hex').toUpperCase();
}

server.listen(4000, () => {
    console.log('listening on *:4000');
});