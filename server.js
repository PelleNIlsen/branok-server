const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

const jwtSecret = 'HNFJKADSGHFy7uiewgeyuf';

const app = express();

app.use(cors({
     origin: '*',
}));
app.options('*', cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const db = mysql.createConnection({
    host: 'sql32.mcb.webhuset.no',
    user: '186366_branok',
    password: '927drefyNO',
    database: '186366_branok',
});

db.connect(err => {
    if (err) throw err;
    console.log('Connected to the database.');
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, (err, user) => {
        console.log('Verifying Token:', token);
        console.log('Verifying Secret:', jwtSecret);
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/news', upload.single('image'), (req, res) => {
    const { type, title, content, author } = req.body;
    console.log('req.file:', req.file);
    console.log('req.body:', req.body);
    const imagePath = `/uploads/${req.file.filename}`;
    const sql = `INSERT INTO News (Type, Image, Title, Content, Author) VALUES (?, ?, ?, ?, ?)`;
    db.query(sql, [type, imagePath, title, content, author], (err, result) => {
        if (err) throw err;
        res.send({ message: 'News entry created.', id: result.insertId });
    });
});

app.get('/news', (req, res) => {
    db.query('SELECT * FROM News ORDER BY WrittenOn DESC', (err, results) => {
        if (err) throw err;
        res.send(results);
    });
});

app.get('/news/:id', (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM News WHERE id = ?', [id], (err, results) => {
        if (err) throw err;
        res.send(results[0]);
    });
});

app.post('/membership', (req, res) => {
    const { fullName, phoneNumber, emailAddress, faxAddress } = req.body;
    const sql = `INSERT INTO Members (FullName, PhoneNumber, EmailAddress, FaxAddress) VALUES (?, ?, ?, ?)`;
    db.query(sql, [fullName, phoneNumber, emailAddress, faxAddress], (err, result) => {
        if (err) throw err;
        res.send({ message: 'Member added.', id: result.insertId });
    });
});

app.get('/members', (req, res) => {
    db.query('SELECT * FROM Members', (err, results) => {
        if (err) throw err;
        res.send(results);
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM AdminUsers WHERE username = ?';

    db.query(sql, [username], (err, results) => {
        if (err) throw err;

        if (results.length === 0) {
            res.status(401).send({ message: 'Authentification failed' });
        } else {
            const user = results[0];
            if (password === user.password) {
                const token = jwt.sign({ userId: results[0].id }, jwtSecret, {
                    expiresIn: '1h'
                });
                console.log('Login Token:', token);
                console.log('Signing Secret:', jwtSecret);
                res.send({ message: 'Authentification successful', token });
            } else {
                res.status(401).send({ message: 'Authentification failed' });
            }
        }
    });
});

app.get('/check-auth', authenticateToken, (req, res) => {
    res.send({ message: 'Authenticated' });
});

app.get('/', (req, res) => {
    res.send('Server is active.');
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on https://server.pellenilsen.no. Port: ${PORT}`);
});
