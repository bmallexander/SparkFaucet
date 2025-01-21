require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');

const Sequelize = require('sequelize');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SequelizeStore = require('connect-session-sequelize')(session.Store);

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(session({
    secret: 'crypto-faucet-secret',
    resave: false,
    saveUninitialized: true,
}));

// Rate limiting
const claimCooldown = 30 * 60 * 1000; // 30 minutes in milliseconds

// Database Initialization
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'faucet.db',
});

// User Model
const User = sequelize.define('user', {
    username: { type: Sequelize.STRING, unique: true, allowNull: false },
    email: { type: Sequelize.STRING, unique: true, allowNull: false },
    password: { type: Sequelize.STRING, allowNull: false },
});

// Sync Database
sequelize.sync();

// Session Store
const sessionStore = new SequelizeStore({ db: sequelize });
app.use(session({
    secret: 'crypto-faucet-secret',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
}));
sessionStore.sync();

// Middleware to check login
function isAuthenticated(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

// Routes

// Claim Screen
app.get('/claim', isAuthenticated, (req, res) => {
    res.render('claim', { message: null });
});

app.post('/claim', isAuthenticated, async (req, res) => {
    const { address, captchaToken } = req.body;

    // Validate CAPTCHA
    const captchaResponse = await axios.post(
        `https://www.google.com/recaptcha/api/siteverify`,
        null,
        {
            params: {
                secret: process.env.CAPTCHA_SECRET,
                response: captchaToken,
            },
        }
    );

    if (!captchaResponse.data.success) {
        return res.render('claim', { message: 'CAPTCHA validation failed.' });
    }

    // Check cooldown
    const lastClaim = req.session.lastClaim || 0;
    const now = Date.now();
    if (now - lastClaim < claimCooldown) {
        const waitTime = Math.ceil((claimCooldown - (now - lastClaim)) / 60000);
        return res.render('claim', { message: `You can claim again in ${waitTime} minutes.` });
    }

    // FaucetPay API Request
    try {
        const response = await axios.post('https://faucetpay.io/api/v1/send', null, {
            params: {
                api_key: process.env.FAUCETPAY_API_KEY,
                to: address,
                amount: 0.001, // Change this to your desired amount
                currency: 'BTC', // Change to desired currency
            },
        });

        if (response.data.status === 200) {
            req.session.lastClaim = now;
            res.render('claim', { message: 'Claim successful! Funds sent to your address.' });
        } else {
            res.render('claim', { message: `Error: ${response.data.message}` });
        }
    } catch (error) {
        res.render('claim', { message: 'An error occurred. Please try again later.' });
    }
});

// Registration Page
app.get('/register', (req, res) => {
    res.render('register', { message: null });
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, email, password: hashedPassword });
        res.redirect('/login');
    } catch (error) {
        res.render('register', { message: 'Error: Username or email already exists.' });
    }
});

// Login Page
app.get('/login', (req, res) => {
    res.render('login', { message: null });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user.id;
        res.redirect('/dashboard');
    } else {
        res.render('login', { message: 'Invalid email or password.' });
    }
});

// Dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard');
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Start the server
app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});
