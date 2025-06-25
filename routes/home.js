const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    res.render('home'); // This will render views/home.ejs
});

module.exports = router;
