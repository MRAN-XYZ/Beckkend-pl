const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises; // Use promises
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3030;
const usersFilePath = path.join(__dirname, 'users.json');

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Sign-up route
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    // Validasi input
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Username, email, and password are required' });
    }

    try {
        const data = await fs.readFile(usersFilePath, 'utf8');
        const users = data ? JSON.parse(data) : [];

        // Cek jika username sudah ada
        if (users.find(user => user.username === username)) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = bcrypt.hashSync(password, 10);
        users.push({ username, email, password: hashedPassword });

        // Simpan ke users.json
        await fs.writeFile(usersFilePath, JSON.stringify(users, null, 2));
        res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
        console.error('Error reading or saving user data:', err);
        res.status(500).json({ message: 'Error processing user data' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Validasi input
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const data = await fs.readFile(usersFilePath, 'utf8');
        const users = JSON.parse(data);

        const user = users.find(user => user.username === username);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password.' });
        }

        res.status(200).json({ message: 'Login successful.' });
    } catch (err) {
        console.error('Error reading user data:', err);
        res.status(500).json({ message: 'Error reading user data' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
