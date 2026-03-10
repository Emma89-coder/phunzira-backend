// utils/helpers.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config/config');

class Helpers {
    // Password hashing
    static async hashPassword(password) {
        return await bcrypt.hash(password, config.BCRYPT_SALT_ROUNDS);
    }

    static async comparePassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    // JWT tokens
    static generateToken(user) {
        return jwt.sign(
            {
                id: user.id,
                uuid: user.uuid,
                username: user.username,
                email: user.email,
                role: user.role
            },
            config.JWT_SECRET,
            { expiresIn: config.JWT_EXPIRE }
        );
    }

    static generateRefreshToken(user) {
        return jwt.sign(
            { id: user.id },
            config.JWT_REFRESH_SECRET,
            { expiresIn: config.JWT_REFRESH_EXPIRE }
        );
    }

    static verifyToken(token) {
        return jwt.verify(token, config.JWT_SECRET);
    }

    static verifyRefreshToken(token) {
        return jwt.verify(token, config.JWT_REFRESH_SECRET);
    }

    // Random tokens
    static generateRandomToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    static generateNumericCode(length = 6) {
        return Math.floor(Math.random() * Math.pow(10, length))
            .toString()
            .padStart(length, '0');
    }

    // Date helpers
    static addMinutes(date, minutes) {
        return new Date(date.getTime() + minutes * 60000);
    }

    static addHours(date, hours) {
        return new Date(date.getTime() + hours * 3600000);
    }

    static addDays(date, days) {
        return new Date(date.getTime() + days * 86400000);
    }

    // Data sanitization
    static sanitizeUser(user) {
        const { password_hash, ...sanitizedUser } = user;
        return sanitizedUser;
    }

    // IP and device info
    static getClientInfo(req) {
        return {
            ip_address: req.ip ||
                       req.connection.remoteAddress ||
                       req.socket.remoteAddress ||
                       req.headers['x-forwarded-for']?.split(',')[0],
            user_agent: req.headers['user-agent'],
            device_info: `${req.headers['user-agent']} - ${req.headers['accept-language']}`
        };
    }

    // Response formatter
    static formatResponse(success, message, data = null, errors = null) {
        const response = { success, message };
        if (data) response.data = data;
        if (errors) response.errors = errors;
        return response;
    }

    // Error handler
    static handleError(res, error, statusCode = 500) {
        console.error('❌ Error:', error);

        if (config.NODE_ENV === 'development') {
            return res.status(statusCode).json({
                success: false,
                message: error.message,
                stack: error.stack
            });
        }

        return res.status(statusCode).json({
            success: false,
            message: 'Internal server error'
        });
    }

    // Validate email
    static isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    // Validate phone
    static isValidPhone(phone) {
        const phoneRegex = /^[\d\s\-+()]{10,}$/;
        return phoneRegex.test(phone);
    }

    // Pagination
    static getPaginationParams(page, limit) {
        const pageNum = parseInt(page) || 1;
        const limitNum = parseInt(limit) || 10;
        const offset = (pageNum - 1) * limitNum;

        return {
            page: pageNum,
            limit: limitNum,
            offset,
            hasNext: false
        };
    }
}

module.exports = Helpers;