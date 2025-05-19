const { pool } = require('./database');

async function initializeDatabase() {
    try {
        // Create users table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create files table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                originalname VARCHAR(255) NOT NULL,
                mimetype VARCHAR(100) NOT NULL,
                size INT NOT NULL,
                path VARCHAR(255) NOT NULL,
                user_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Create file_shares table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS file_shares (
                id INT AUTO_INCREMENT PRIMARY KEY,
                file_id INT NOT NULL,
                shared_with_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (shared_with_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        console.log('Database tables created successfully');
    } catch (error) {
        console.error('Error initializing database:', error);
        process.exit(1);
    }
}

// Run initialization if this file is run directly
if (require.main === module) {
    initializeDatabase();
}

module.exports = initializeDatabase; 