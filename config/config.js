// config/config.js
require('dotenv').config();

module.exports = {
    // Server config
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: process.env.PORT || 5000,

    // Database config
    DATABASE_URL: process.env.DATABASE_URL,

    // Individual database credentials (fallback if DATABASE_URL not provided)
    DB_USER: process.env.DB_USER,
    DB_HOST: process.env.DB_HOST,
    DB_NAME: process.env.DB_NAME,
    DB_PASSWORD: process.env.DB_PASSWORD,
    DB_PORT: process.env.DB_PORT || 5432,

    // JWT config
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRE: process.env.JWT_EXPIRE || '7d',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    JWT_REFRESH_EXPIRE: process.env.JWT_REFRESH_EXPIRE || '30d',

    // Additional JWT tokens for specific purposes
    JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET,
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    JWT_VERIFY_SECRET: process.env.JWT_VERIFY_SECRET || process.env.JWT_SECRET,
    JWT_RESET_SECRET: process.env.JWT_RESET_SECRET || process.env.JWT_SECRET,

    // Token expiry times
    JWT_ACCESS_EXPIRY: process.env.JWT_ACCESS_EXPIRY || '15m',
    JWT_REFRESH_EXPIRY: process.env.JWT_REFRESH_EXPIRY || '7d',
    JWT_VERIFY_EXPIRY: process.env.JWT_VERIFY_EXPIRY || '24h',
    JWT_RESET_EXPIRY: process.env.JWT_RESET_EXPIRY || '1h',

    // Bcrypt config
    BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10,

    // Rate limiting
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15,
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,

    // CORS config - INCLUDING YOUR DEPLOYED FRONTEND
    CORS_ORIGINS: process.env.CORS_ORIGINS
        ? process.env.CORS_ORIGINS.split(',').map(origin => origin.trim())
        : [
            'http://localhost:3000',
            'http://localhost:5000',
            'https://phunziraa.netlify.app'
          ],

    // Frontend URL for email links
    FRONTEND_URL: process.env.FRONTEND_URL || 'https://phunziraa.netlify.app',

    // Validate required config
    validateConfig() {
        const required = ['JWT_SECRET'];

        // Either DATABASE_URL or individual DB credentials must be provided
        if (!process.env.DATABASE_URL && !(process.env.DB_USER && process.env.DB_HOST && process.env.DB_NAME && process.env.DB_PASSWORD)) {
            throw new Error('Database connection details missing. Provide either DATABASE_URL or DB_USER, DB_HOST, DB_NAME, DB_PASSWORD');
        }

        const missing = required.filter(key => !process.env[key]);

        if (missing.length > 0) {
            throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
        }

        if (this.JWT_SECRET && this.JWT_SECRET.length < 32) {
            console.warn('⚠️ JWT_SECRET should be at least 32 characters long for security');
        }

        // Log active configuration (without sensitive data)
        console.log('📋 Configuration loaded:');
        console.log(`   - Environment: ${this.NODE_ENV}`);
        console.log(`   - Port: ${this.PORT}`);
        console.log(`   - Database: ${this.DATABASE_URL ? 'Using DATABASE_URL' : 'Using individual credentials'}`);
        console.log(`   - Frontend URL: ${this.FRONTEND_URL}`);
        console.log(`   - CORS Origins: ${this.CORS_ORIGINS.join(', ')}`);
        console.log(`   - Rate Limit: ${this.RATE_LIMIT_MAX} requests per ${this.RATE_LIMIT_WINDOW} minutes`);

        return true;
    },

    // Helper to get database connection config
    getDbConfig() {
        if (this.DATABASE_URL) {
            return {
                connectionString: this.DATABASE_URL,
                ssl: this.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
            };
        }

        return {
            user: this.DB_USER,
            host: this.DB_HOST,
            database: this.DB_NAME,
            password: this.DB_PASSWORD,
            port: this.DB_PORT,
            ssl: this.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        };
    },

    // Helper to check if running in production
    isProduction() {
        return this.NODE_ENV === 'production';
    },

    // Helper to check if running in development
    isDevelopment() {
        return this.NODE_ENV === 'development';
    }
};