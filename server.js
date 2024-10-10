const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const cors = require('cors'); // Import CORS untuk memungkinkan permintaan dari domain berbeda

const app = express();
const PORT = process.env.PORT || 3030; // Gunakan port dari environment variable atau 3030 jika tidak ada

// Middleware
app.use(bodyParser.json());
app.use(cors()); // Mengizinkan semua origin untuk berkomunikasi dengan server

// Path ke file users.json
const usersFilePath = path.join(__dirname, 'users.json');

// Sign-up route
app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;

    // Validasi input
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
            users = JSON.parse(data); // Parse jika ada data
        }
        
        // Cek jika username sudah ada
        if (users.find(user => user.username === username)) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        // Tambahkan user baru
        users.push({ username, email, password: hashedPassword });

        // Simpan ke users.json
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

    // Validasi input
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
        
        // Cari user berdasarkan username
        const user = users.find(user => user.username === username);
        if (!user) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'User not found.' });
        }

        // Bandingkan password
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