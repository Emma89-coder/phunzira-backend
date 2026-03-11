// middleware/auth.js
const jwt = require('jsonwebtoken');
const db = require('../utils/db');
const config = require('../config/config');
const Helpers = require('../utils/helpers');
const rateLimit = require('express-rate-limit');
const Redis = require('ioredis'); // For better token blacklisting

class AuthMiddleware {
    // Initialize Redis client for token blacklisting
    static redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

    // Verify access token with enhanced security
    static async authenticateToken(req, res, next) {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Access token required')
                );
            }

            // Check if token is blacklisted
            const isBlacklisted = await AuthMiddleware.isTokenBlacklisted(token);
            if (isBlacklisted) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Token has been revoked')
                );
            }

            const decoded = Helpers.verifyToken(token);

            // Enhanced user validation
            const result = await db.query(
                `SELECT id, username, email, role, is_active,
                        token_version, last_login_ip, last_login_at
                 FROM users
                 WHERE id = $1 AND is_active = true`,
                [decoded.id]
            );

            if (result.rows.length === 0) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'User not found or inactive')
                );
            }

            const user = result.rows[0];

            // Check token version (for forcing logout all devices)
            if (user.token_version !== decoded.token_version) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Token version invalid. Please login again.')
                );
            }

            // Optional: Check IP binding if enabled
            if (config.security.bindTokenToIP) {
                const clientIp = req.ip || req.connection.remoteAddress;
                if (decoded.ip !== clientIp) {
                    return res.status(401).json(
                        Helpers.formatResponse(false, 'IP address mismatch')
                    );
                }
            }

            // Optional: Check user agent binding
            if (config.security.bindTokenToUserAgent) {
                const userAgent = req.get('User-Agent');
                if (decoded.userAgent !== userAgent) {
                    return res.status(401).json(
                        Helpers.formatResponse(false, 'User agent mismatch')
                    );
                }
            }

            // Attach full user object to request
            req.user = {
                ...decoded,
                ...user
            };

            // Update last activity (optional - can be done asynchronously)
            AuthMiddleware.updateLastActivity(user.id).catch(err =>
                console.error('Failed to update last activity:', err)
            );

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

    // Token blacklisting methods
    static async isTokenBlacklisted(token) {
        try {
            if (AuthMiddleware.redis) {
                // Use Redis for faster blacklist checking
                const exists = await AuthMiddleware.redis.get(`blacklist:${token}`);
                return !!exists;
            } else {
                // Fallback to database
                const result = await db.query(
                    'SELECT 1 FROM token_blacklist WHERE token = $1 AND expires_at > NOW()',
                    [token]
                );
                return result.rows.length > 0;
            }
        } catch (err) {
            console.error('Error checking token blacklist:', err);
            return false; // Fail open or closed? Choose based on security requirements
        }
    }

    static async blacklistToken(token, expiresIn) {
        try {
            if (AuthMiddleware.redis) {
                await AuthMiddleware.redis.set(
                    `blacklist:${token}`,
                    '1',
                    'EX',
                    expiresIn
                );
            } else {
                await db.query(
                    'INSERT INTO token_blacklist (token, expires_at) VALUES ($1, NOW() + interval \'$2 seconds\')',
                    [token, expiresIn]
                );
            }
        } catch (err) {
            console.error('Error blacklisting token:', err);
        }
    }

    // Refresh token authentication with device tracking
    static async authenticateRefreshToken(req, res, next) {
        try {
            const { refreshToken } = req.body;
            const deviceId = req.get('X-Device-ID') || req.headers['user-agent'];

            if (!refreshToken) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Refresh token required')
                );
            }

            // Verify token
            const decoded = Helpers.verifyRefreshToken(refreshToken);

            // Enhanced refresh token validation with device tracking
            const result = await db.query(
                `SELECT rt.*, u.token_version, u.is_active
                 FROM refresh_tokens rt
                 JOIN users u ON u.id = rt.user_id
                 WHERE rt.token = $1
                 AND rt.expires_at > NOW()
                 AND (rt.device_id = $2 OR rt.device_id IS NULL)
                 AND rt.revoked_at IS NULL`,
                [refreshToken, deviceId]
            );

            if (result.rows.length === 0) {
                // Possible token theft - revoke all tokens for this user
                if (decoded && decoded.id) {
                    await AuthMiddleware.revokeAllUserTokens(decoded.id, 'Possible token theft');
                }
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Invalid or expired refresh token')
                );
            }

            const tokenData = result.rows[0];

            // Check if user is still active
            if (!tokenData.is_active) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'User account is inactive')
                );
            }

            // Check token version
            if (tokenData.token_version !== decoded.token_version) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Token version mismatch')
                );
            }

            req.user = decoded;
            req.refreshToken = refreshToken;
            req.refreshTokenId = tokenData.id;
            next();
        } catch (err) {
            return Helpers.handleError(res, err);
        }
    }

    // Revoke all tokens for a user
    static async revokeAllUserTokens(userId, reason = 'Manual revoke') {
        try {
            await db.query(
                `UPDATE refresh_tokens
                 SET revoked_at = NOW(), revoked_reason = $2
                 WHERE user_id = $1 AND revoked_at IS NULL`,
                [userId, reason]
            );

            // Increment token version to invalidate all JWTs
            await db.query(
                'UPDATE users SET token_version = token_version + 1 WHERE id = $1',
                [userId]
            );
        } catch (err) {
            console.error('Error revoking user tokens:', err);
        }
    }

    // Optional authentication with device info
    static async optionalAuth(req, res, next) {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];

            if (token) {
                const isBlacklisted = await AuthMiddleware.isTokenBlacklisted(token);
                if (!isBlacklisted) {
                    try {
                        const decoded = Helpers.verifyToken(token);
                        req.user = decoded;
                    } catch (err) {
                        // Invalid token, just ignore
                    }
                }
            }
            next();
        } catch (err) {
            next();
        }
    }

    // Role-based authorization with hierarchy
    static authorize(roles = []) {
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Authentication required')
                );
            }

            const userRole = req.user.role;

            // Role hierarchy
            const roleHierarchy = {
                'admin': 3,
                'teacher': 2,
                'learner': 1
            };

            const requiredRoleLevel = Math.max(...roles.map(r => roleHierarchy[r] || 0));
            const userRoleLevel = roleHierarchy[userRole] || 0;

            if (userRoleLevel >= requiredRoleLevel) {
                return next();
            }

            return res.status(403).json(
                Helpers.formatResponse(false, 'Insufficient permissions')
            );
        };
    }

    // Specific role checks (convenience methods)
    static isAdmin(req, res, next) {
        return AuthMiddleware.authorize(['admin'])(req, res, next);
    }

    static isTeacherOrAdmin(req, res, next) {
        return AuthMiddleware.authorize(['teacher', 'admin'])(req, res, next);
    }

    // Resource ownership check with role override
    static async isOwnerOrAdmin(req, res, next) {
        try {
            const userId = parseInt(req.params.userId);

            // Admin can access any resource
            if (req.user.role === 'admin') {
                return next();
            }

            // Check if user owns the resource
            if (req.user.id === userId) {
                return next();
            }

            // Check if teacher owns the course/lesson (example)
            if (req.params.courseId && req.user.role === 'teacher') {
                const result = await db.query(
                    'SELECT 1 FROM courses WHERE id = $1 AND teacher_id = $2',
                    [req.params.courseId, req.user.id]
                );
                if (result.rows.length > 0) {
                    return next();
                }
            }

            return res.status(403).json(
                Helpers.formatResponse(false, 'Access denied')
            );
        } catch (err) {
            return Helpers.handleError(res, err);
        }
    }

    // Rate limiting factory with different limits for different endpoints
    static createRateLimiter(options = {}) {
        const defaults = {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100, // Default 100 requests per window
            message: Helpers.formatResponse(false, 'Too many requests, please try again later'),
            standardHeaders: true,
            legacyHeaders: false,
            keyGenerator: (req) => {
                // Use user ID if authenticated, otherwise IP
                return req.user?.id || req.ip;
            }
        };

        const config = { ...defaults, ...options };

        return rateLimit(config);
    }

    // Predefined rate limiters
    static authRateLimiter = AuthMiddleware.createRateLimiter({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // 5 attempts per window
        skipSuccessfulRequests: true,
    });

    static apiRateLimiter = AuthMiddleware.createRateLimiter({
        windowMs: 60 * 1000, // 1 minute
        max: 60, // 60 requests per minute
    });

    // Update user's last activity
    static async updateLastActivity(userId) {
        try {
            await db.query(
                'UPDATE users SET last_activity_at = NOW() WHERE id = $1',
                [userId]
            );
        } catch (err) {
            console.error('Failed to update last activity:', err);
        }
    }

    // Get active sessions for a user
    static async getUserSessions(userId) {
        try {
            const result = await db.query(
                `SELECT id, device_id, created_at, expires_at,
                        last_used_at, ip_address, user_agent
                 FROM refresh_tokens
                 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
                 ORDER BY last_used_at DESC`,
                [userId]
            );
            return result.rows;
        } catch (err) {
            console.error('Error getting user sessions:', err);
            return [];
        }
    }

    // Revoke specific session
    static async revokeSession(tokenId, userId) {
        try {
            await db.query(
                'UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND user_id = $2',
                [tokenId, userId]
            );
            return true;
        } catch (err) {
            console.error('Error revoking session:', err);
            return false;
        }
    }
}

module.exports = AuthMiddleware;