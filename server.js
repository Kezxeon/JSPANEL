
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');   // <-- ADD THIS
const { randomString, hmacSHA256, aesGcmEncrypt } = require('./utils');;

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage of keys for simplicity
const issuedKeys = {}; 

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// Frontend: simple form to generate key
app.get('/', (req, res) => {
    res.render('index', { generated: null });
});

// Generate key endpoint
app.post('/generate', (req, res) => {
    const { userKey } = req.body;
    if (!userKey || userKey.length < 3) return res.send("Invalid user key");

    const srcStr = randomString(16);
    const now = Math.floor(Date.now() / 1000);
    const UUID = crypto.createHash('md5').update(userKey).digest('hex');

    // Fake payload structure like Android expects
    const payloadObj = {
        status: 945734,
        data: {
            token: crypto.createHash('md5').update(userKey).digest('hex'),
            rng: now,
            expiredDate: (now + 3600).toString(), // 1 hour expiry
            checked: crypto.createHash('md5').update(userKey + UUID).digest('hex')
        }
    };

    const payloadJson = JSON.stringify(payloadObj);
    const payloadB64 = aesGcmEncrypt(payloadJson);
    const sig = hmacSHA256(payloadB64);

    // Store for testing if needed
    issuedKeys[userKey] = { payloadB64, sig, created: now };

    res.render('index', { generated: { payloadB64, sig } });
});

// Health check
app.get('/ping', (req, res) => res.send('pong'));

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
