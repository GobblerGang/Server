const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
require('dotenv').config();
const { testConnection } = require('./config/database');
const initializeDatabase = require('./config/init-db');

// Create Express app
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? 'https://yourdomain.com' : '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/files', require('./routes/files'));
app.use('/api/users', require('./routes/users'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Initialize database and start server
async function startServer() {
    try {
        console.log('Starting server initialization...');
        console.log('Environment variables:', {
            DB_HOST: process.env.DB_HOST,
            DB_USER: process.env.DB_USER,
            DB_NAME: process.env.DB_NAME,
            NODE_ENV: process.env.NODE_ENV
        });

        // Test database connection
        console.log('Testing database connection...');
        await testConnection();
        
        // Initialize database tables
        console.log('Initializing database tables...');
        await initializeDatabase();
        
        // Start server
        const startPort = parseInt(process.env.PORT) || 3000;
        const maxPort = startPort + 10; // Try up to 10 ports

        for (let port = startPort; port < maxPort; port++) {
            try {
                await new Promise((resolve, reject) => {
                    const server = app.listen(port, () => {
                        console.log(`Server is running on port ${port}`);
                        resolve();
                    }).on('error', (err) => {
                        if (err.code === 'EADDRINUSE') {
                            console.log(`Port ${port} is in use, trying ${port + 1}...`);
                            reject(err);
                        } else {
                            reject(err);
                        }
                    });
                });
                break; // If we get here, the server started successfully
            } catch (err) {
                if (port === maxPort - 1) {
                    throw new Error('No available ports found');
                }
                // Continue to next port
            }
        }
    } catch (error) {
        console.error('Failed to start server. Error details:', error);
        console.error('Stack trace:', error.stack);
        process.exit(1);
    }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    console.error('Stack trace:', error.stack);
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise);
    console.error('Reason:', reason);
    process.exit(1);
});

startServer(); 