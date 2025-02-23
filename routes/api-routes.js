const router = require('express').Router();
const bcrypt = require('bcrypt');
const db = require('../db');
const checkAuth = require('../middleware/auth');

router.post('/checkout', checkAuth, (req, res) => {
    res.json({ message: 'Checkout completed successfully' });
});

router.post('/user', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Username and password required');

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        res.redirect('/login');
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).send('User already exists');
        res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Username and password required');

    const [[user]] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(400).send('Invalid username or password');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid username or password');

    req.session.loggedIn = true;
    req.session.userId = user.id;
    req.session.save(() => res.redirect('/'));
});

router.get('/logout', async (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

module.exports = router;
