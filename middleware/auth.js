// middleware/auth.js
const jwt = require('jsonwebtoken');
const db = require('../utils/db');
const config = require('../config/config');
const Helpers = require('../utils/helpers');

class AuthMiddleware {
    // Verify access token
    static async authenticateToken(req, res, next) {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Access token required')
                );
            }

            const decoded = Helpers.verifyToken(token);

            // Check if user still exists
            const result = await db.query(
                'SELECT id, username, email, role, is_active FROM users WHERE id = $1 AND is_active = true',
                [decoded.id]
            );

            if (result.rows.length === 0) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'User not found or inactive')
                );
            }

            req.user = decoded;
            next();
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Token expired')
                );
            }
            if (err.name === 'JsonWebTokenError') {
                return res.status(403).json(
                    Helpers.formatResponse(false, 'Invalid token')
                );
            }
            return Helpers.handleError(res, err);
        }
    }

    // Optional authentication (doesn't fail if no token)
    static async optionalAuth(req, res, next) {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];

            if (token) {
                const decoded = Helpers.verifyToken(token);
                req.user = decoded;
            }
            next();
        } catch (err) {
            // Just continue without user
            next();
        }
    }

    // Refresh token authentication
    static async authenticateRefreshToken(req, res, next) {
        try {
            const { refreshToken } = req.body;

            if (!refreshToken) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Refresh token required')
                );
            }

            // Verify token
            const decoded = Helpers.verifyRefreshToken(refreshToken);

            // Check if refresh token exists in database
            const result = await db.query(
                'SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()',
                [refreshToken]
            );

            if (result.rows.length === 0) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Invalid or expired refresh token')
                );
            }

            req.user = decoded;
            req.refreshToken = refreshToken;
            next();
        } catch (err) {
            return Helpers.handleError(res, err);
        }
    }

    // Check if user is admin
    static async isAdmin(req, res, next) {
        if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json(
                Helpers.formatResponse(false, 'Admin access required')
            );
        }
        next();
    }

    // Check if user is teacher or admin
    static async isTeacherOrAdmin(req, res, next) {
        if (!req.user || !['teacher', 'admin'].includes(req.user.role)) {
            return res.status(403).json(
                Helpers.formatResponse(false, 'Teacher or admin access required')
            );
        }
        next();
    }

    // Check if user owns the resource or is admin
    static async isOwnerOrAdmin(req, res, next) {
        try {
            const userId = parseInt(req.params.userId);

            if (req.user.role === 'admin' || req.user.id === userId) {
                return next();
            }

            return res.status(403).json(
                Helpers.formatResponse(false, 'Access denied')
            );
        } catch (err) {
            return Helpers.handleError(res, err);
        }
    }

    // Rate limiting for auth endpoints
    static authRateLimiter = require('express-rate-limit')({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // 5 attempts per window
        message: Helpers.formatResponse(false, 'Too many attempts, please try again later'),
        skipSuccessfulRequests: true,
        standardHeaders: true,
        legacyHeaders: false,
    });
}

module.exports = AuthMiddleware;