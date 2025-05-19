const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const auth = require('../middleware/auth');
const { pool } = require('../config/database');

// Get user profile
router.get('/profile', auth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [users] = await pool.execute(
            'SELECT id, username, email, created_at FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: users[0] });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Error fetching user profile' });
    }
});

// Update user profile
router.put('/profile', auth, async (req, res) => {
    try {
        const userId = req.user.id;
        const { username, email } = req.body;

        // Validate input
        if (!username || !email) {
            return res.status(400).json({ error: 'Username and email are required' });
        }

        // Check if username or email is already taken
        const [existingUsers] = await pool.execute(
            'SELECT * FROM users WHERE (username = ? OR email = ?) AND id != ?',
            [username, email, userId]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'Username or email already taken' });
        }

        // Update user
        await pool.execute(
            'UPDATE users SET username = ?, email = ? WHERE id = ?',
            [username, email, userId]
        );

        res.json({
            message: 'Profile updated successfully',
            user: { id: userId, username, email }
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Error updating profile' });
    }
});

// Change password
router.put('/change-password', auth, async (req, res) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        // Validate input
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new passwords are required' });
        }

        // Get current user
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE id = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = users[0];

        // Verify current password
        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        await pool.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, userId]
        );

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Error changing password' });
    }
});

// Search users
router.get('/search', auth, async (req, res) => {
    try {
        const { query } = req.query;

        if (!query) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        const [users] = await pool.execute(
            'SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ?',
            [`%${query}%`, `%${query}%`]
        );

        res.json({ users });
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({ error: 'Error searching users' });
    }
});

module.exports = router; 