const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const cors = require('cors'); // Import CORS for cross-origin requests

const app = express();
const PORT = process.env.PORT || 3030; // Use port from environment variable or default to 3030

// Middleware
app.use(bodyParser.json());
app.use(cors()); // Allow all origins to communicate with the server

// Path to users.json file
const usersFilePath = path.join(__dirname, 'users.json');

// Root route (GET /)
app.get('/', (req, res) => {
    res.send('Welcome to the User Authentication API');
});

// Sign-up route
app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
        console.log('Missing fields in signup');
        return res.status(400).json({ message: 'Username, email, and password are required' });
    }

    // Load users
    fs.readFile(usersFilePath, 'utf8', (err, data) => {
        if (err) {
            console.log('Error reading user data:', err);
            return res.status(500).json({ message: 'Error reading user data' });
        }

        let users = [];

        if (data) {
            users = JSON.parse(data); // Parse if data exists
        }

        // Check if username already exists
        if (users.find(user => user.username === username)) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Add new user
        users.push({ username, email, password: hashedPassword });

        // Save to users.json
        fs.writeFile(usersFilePath, JSON.stringify(users, null, 2), (err) => {
            if (err) {
                console.log('Error saving user data:', err);
                return res.status(500).json({ message: 'Error saving user data' });
            }
            console.log('User created successfully:', username);
            res.status(201).json({ message: 'User created successfully' });
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        console.log('Missing username or password');
        return res.status(400).json({ message: 'Username and password are required' });
    }

    // Load users
    fs.readFile(usersFilePath, 'utf8', (err, data) => {
        if (err) {
            console.log('Error reading user data:', err);
            return res.status(500).json({ message: 'Error reading user data' });
        }

        const users = JSON.parse(data);

        // Find user by username
        const user = users.find(user => user.username === username);
        if (!user) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'User not found.' });
        }

        // Compare password
        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            console.log('Invalid password for user:', username);
            return res.status(401).json({ message: 'Invalid password.' });
        }

        console.log('Login successful for user:', username);
        res.status(200).json({ message: 'Login successful.' });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
