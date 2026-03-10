// config/config.js
require('dotenv').config();

module.exports = {
    // Server config
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: process.env.PORT || 5000,

    // Database config
    DATABASE_URL: process.env.DATABASE_URL,

    // JWT config
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRE: process.env.JWT_EXPIRE || '7d',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    JWT_REFRESH_EXPIRE: process.env.JWT_REFRESH_EXPIRE || '30d',

    // Bcrypt config
    BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10,

    // Rate limiting
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 15,
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,

    // CORS config
    CORS_ORIGINS: process.env.CORS_ORIGINS
        ? process.env.CORS_ORIGINS.split(',')
        : ['http://localhost:3000', 'http://localhost:5000'],

    // Validate required config
    validateConfig() {
        const required = ['JWT_SECRET', 'DATABASE_URL'];
        const missing = required.filter(key => !process.env[key]);

        if (missing.length > 0) {
            throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
        }

        if (this.JWT_SECRET.length < 32) {
            console.warn('⚠️ JWT_SECRET should be at least 32 characters long for security');
        }

        return true;
    }
};