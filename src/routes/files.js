const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const auth = require('../middleware/auth');
const { pool } = require('../config/database');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '../../uploads'));
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 100000000 // 100MB default
    }
});

// Upload file
router.post('/upload', auth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const { originalname, filename, size, mimetype } = req.file;
        const userId = req.user.id;

        // Store file metadata in database
        const [result] = await pool.execute(
            'INSERT INTO files (user_id, filename, originalname, mimetype, size, path) VALUES (?, ?, ?, ?, ?, ?)',
            [userId, filename, originalname, mimetype, size, path.join('uploads', filename)]
        );

        res.status(201).json({
            message: 'File uploaded successfully',
            file: {
                id: result.insertId,
                filename: filename,
                originalname: originalname,
                size,
                mimetype: mimetype
            }
        });
    } catch (error) {
        console.error('File upload error:', error);
        res.status(500).json({ error: 'Error uploading file' });
    }
});

// Get user's files
router.get('/', auth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [files] = await pool.execute(
            `SELECT f.*, u.username as owner_name 
             FROM files f 
             JOIN users u ON f.user_id = u.id 
             WHERE f.user_id = ?`,
            [userId]
        );

        res.json(files);
    } catch (error) {
        console.error('Error fetching files:', error);
        res.status(500).json({ error: 'Error fetching files' });
    }
});

// Get shared files
router.get('/shared-with-me', auth, async (req, res) => {
    try {
        const userId = req.user.id;

        const [files] = await pool.execute(
            `SELECT f.*, u.username as owner_name 
             FROM files f 
             JOIN users u ON f.user_id = u.id 
             JOIN file_shares fs ON f.id = fs.file_id 
             WHERE fs.shared_with_id = ?`,
            [userId]
        );

        res.json({ files });
    } catch (error) {
        console.error('Error fetching shared files:', error);
        res.status(500).json({ error: 'Error fetching shared files' });
    }
});

// Share file with user
router.post('/share/:fileId', auth, async (req, res) => {
    try {
        const { fileId } = req.params;
        const { sharedWithId } = req.body;
        const userId = req.user.id;

        // Verify file ownership
        const [files] = await pool.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            [fileId, userId]
        );

        if (files.length === 0) {
            return res.status(404).json({ error: 'File not found or unauthorized' });
        }

        // Check if share already exists
        const [existingShares] = await pool.execute(
            'SELECT * FROM file_shares WHERE file_id = ? AND shared_with_id = ?',
            [fileId, sharedWithId]
        );

        if (existingShares.length > 0) {
            return res.status(400).json({ error: 'File already shared with this user' });
        }

        // Create share
        await pool.execute(
            'INSERT INTO file_shares (file_id, shared_with_id) VALUES (?, ?)',
            [fileId, sharedWithId]
        );

        res.json({ message: 'File shared successfully' });
    } catch (error) {
        console.error('Error sharing file:', error);
        res.status(500).json({ error: 'Error sharing file' });
    }
});

// Revoke file share
router.delete('/share/:fileId/:userId', auth, async (req, res) => {
    try {
        const { fileId, userId } = req.params;
        const ownerId = req.user.id;

        // Verify file ownership
        const [files] = await pool.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            [fileId, ownerId]
        );

        if (files.length === 0) {
            return res.status(404).json({ error: 'File not found or unauthorized' });
        }

        // Remove share
        await pool.execute(
            'DELETE FROM file_shares WHERE file_id = ? AND shared_with_id = ?',
            [fileId, userId]
        );

        res.json({ message: 'File share revoked successfully' });
    } catch (error) {
        console.error('Error revoking file share:', error);
        res.status(500).json({ error: 'Error revoking file share' });
    }
});

// Download file
router.get('/:fileId', auth, async (req, res) => {
    try {
        const { fileId } = req.params;
        const userId = req.user.id;

        // Check if user has access to file
        const [files] = await pool.execute(
            `SELECT f.* FROM files f 
             WHERE f.id = ? AND f.user_id = ?`,
            [fileId, userId]
        );

        if (files.length === 0) {
            return res.status(404).json({ error: 'File not found or unauthorized' });
        }

        const file = files[0];
        const filePath = path.join(__dirname, '../../uploads', file.filename);

        // Check if file exists
        try {
            await fs.access(filePath);
        } catch (error) {
            return res.status(404).json({ error: 'File not found on server' });
        }

        res.download(filePath, file.originalname);
    } catch (error) {
        console.error('Error downloading file:', error);
        res.status(500).json({ error: 'Error downloading file' });
    }
});

// Delete file
router.delete('/:fileId', auth, async (req, res) => {
    try {
        const { fileId } = req.params;
        const userId = req.user.id;

        // Verify file ownership
        const [files] = await pool.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            [fileId, userId]
        );

        if (files.length === 0) {
            return res.status(404).json({ error: 'File not found or unauthorized' });
        }

        const file = files[0];
        const filePath = path.join(__dirname, '../../uploads', file.filename);

        // Delete file from storage
        try {
            await fs.unlink(filePath);
        } catch (error) {
            console.error('Error deleting file from storage:', error);
            // Continue with database cleanup even if file deletion fails
        }

        // Delete file record
        await pool.execute('DELETE FROM files WHERE id = ?', [fileId]);

        res.json({ message: 'File deleted successfully' });
    } catch (error) {
        console.error('Error deleting file:', error);
        res.status(500).json({ error: 'Error deleting file' });
    }
});

module.exports = router; 