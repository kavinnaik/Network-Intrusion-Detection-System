const express = require('express');
const router = express.Router();

router.get('/login', (req, res) => {
    res.send('Google Authentication Login Route');
});

module.exports = router;
