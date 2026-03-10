// controllers/authController.js
const db = require('../utils/db');
const Helpers = require('../utils/helpers');
const config = require('../config/config');

class AuthController {
    // Register new user
    static async register(req, res) {
        const client = await db.pool.connect();

        try {
            await client.query('BEGIN');

            const {
                username,
                email,
                password,
                first_name,
                last_name,
                phone
            } = req.body;

            // Check if user exists
            const existingUser = await client.query(
                'SELECT id FROM users WHERE email = $1 OR username = $2',
                [email, username]
            );

            if (existingUser.rows.length > 0) {
                await client.query('ROLLBACK');
                return res.status(409).json(
                    Helpers.formatResponse(false, 'User with this email or username already exists')
                );
            }

            // Hash password
            const hashedPassword = await Helpers.hashPassword(password);

            // Create user
            const result = await client.query(
                `INSERT INTO users (
                    username, email, password_hash, first_name, last_name, phone
                ) VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, uuid, username, email, first_name, last_name, phone, role, created_at`,
                [username, email, hashedPassword, first_name, last_name, phone]
            );

            const newUser = result.rows[0];

            // Generate tokens
            const accessToken = Helpers.generateToken(newUser);
            const refreshToken = Helpers.generateRefreshToken(newUser);

            // Save refresh token
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO refresh_tokens (user_id, token, device_info, ip_address, expires_at)
                 VALUES ($1, $2, $3, $4, $5)`,
                [
                    newUser.id,
                    refreshToken,
                    clientInfo.device_info,
                    clientInfo.ip_address,
                    Helpers.addDays(new Date(), 30)
                ]
            );

            // Create email verification token (optional)
            const verificationToken = Helpers.generateRandomToken();
            await client.query(
                `INSERT INTO email_verifications (user_id, token, expires_at)
                 VALUES ($1, $2, $3)`,
                [newUser.id, verificationToken, Helpers.addHours(new Date(), 24)]
            );

            // Log action
            await client.query(
                `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [
                    newUser.id,
                    'USER_REGISTERED',
                    'users',
                    newUser.id,
                    clientInfo.ip_address,
                    clientInfo.user_agent
                ]
            );

            await client.query('COMMIT');

            // Remove sensitive data
            delete newUser.password_hash;

            res.status(201).json({
                success: true,
                message: 'Registration successful',
                data: {
                    user: newUser,
                    accessToken,
                    refreshToken
                }
            });

        } catch (err) {
            await client.query('ROLLBACK');
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Login user
    static async login(req, res) {
        const client = await db.pool.connect();

        try {
            const { email, password } = req.body;

            // Find user
            const result = await client.query(
                `SELECT id, uuid, username, email, password_hash, first_name, last_name,
                        phone, role, is_active, is_verified
                 FROM users
                 WHERE email = $1`,
                [email]
            );

            const user = result.rows[0];

            if (!user) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Invalid email or password')
                );
            }

            if (!user.is_active) {
                return res.status(403).json(
                    Helpers.formatResponse(false, 'Account is deactivated')
                );
            }

            // Verify password
            const isValidPassword = await Helpers.comparePassword(password, user.password_hash);

            if (!isValidPassword) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Invalid email or password')
                );
            }

            // Update last login
            await client.query(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
                [user.id]
            );

            // Generate tokens
            const accessToken = Helpers.generateToken(user);
            const refreshToken = Helpers.generateRefreshToken(user);

            // Save refresh token
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO refresh_tokens (user_id, token, device_info, ip_address, expires_at)
                 VALUES ($1, $2, $3, $4, $5)`,
                [
                    user.id,
                    refreshToken,
                    clientInfo.device_info,
                    clientInfo.ip_address,
                    Helpers.addDays(new Date(), 30)
                ]
            );

            // Log action
            await client.query(
                `INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4)`,
                [user.id, 'USER_LOGIN', clientInfo.ip_address, clientInfo.user_agent]
            );

            // Remove sensitive data
            delete user.password_hash;

            res.json({
                success: true,
                message: 'Login successful',
                data: {
                    user,
                    accessToken,
                    refreshToken
                }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Refresh token
    static async refreshToken(req, res) {
        const client = await db.pool.connect();

        try {
            const { refreshToken } = req.body;
            const userId = req.user.id;

            // Delete old refresh token
            await client.query(
                'DELETE FROM refresh_tokens WHERE token = $1',
                [refreshToken]
            );

            // Get user
            const userResult = await client.query(
                `SELECT id, uuid, username, email, first_name, last_name,
                        phone, role, is_active
                 FROM users WHERE id = $1 AND is_active = true`,
                [userId]
            );

            if (userResult.rows.length === 0) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'User not found or inactive')
                );
            }

            const user = userResult.rows[0];

            // Generate new tokens
            const newAccessToken = Helpers.generateToken(user);
            const newRefreshToken = Helpers.generateRefreshToken(user);

            // Save new refresh token
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO refresh_tokens (user_id, token, device_info, ip_address, expires_at)
                 VALUES ($1, $2, $3, $4, $5)`,
                [
                    user.id,
                    newRefreshToken,
                    clientInfo.device_info,
                    clientInfo.ip_address,
                    Helpers.addDays(new Date(), 30)
                ]
            );

            res.json({
                success: true,
                message: 'Token refreshed',
                data: {
                    accessToken: newAccessToken,
                    refreshToken: newRefreshToken
                }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Logout
    static async logout(req, res) {
        const client = await db.pool.connect();

        try {
            const refreshToken = req.body.refreshToken;
            const userId = req.user.id;

            // Delete refresh token
            if (refreshToken) {
                await client.query(
                    'DELETE FROM refresh_tokens WHERE token = $1',
                    [refreshToken]
                );
            }

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4)`,
                [userId, 'USER_LOGOUT', clientInfo.ip_address, clientInfo.user_agent]
            );

            res.json(
                Helpers.formatResponse(true, 'Logout successful')
            );

        } catch (err) {
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Logout from all devices
    static async logoutAll(req, res) {
        const client = await db.pool.connect();

        try {
            const userId = req.user.id;

            // Delete all refresh tokens for user
            await client.query(
                'DELETE FROM refresh_tokens WHERE user_id = $1',
                [userId]
            );

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4)`,
                [userId, 'USER_LOGOUT_ALL', clientInfo.ip_address, clientInfo.user_agent]
            );

            res.json(
                Helpers.formatResponse(true, 'Logged out from all devices')
            );

        } catch (err) {
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Forgot password
    static async forgotPassword(req, res) {
        const client = await db.pool.connect();

        try {
            const { email } = req.body;

            // Find user
            const userResult = await client.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );

            if (userResult.rows.length > 0) {
                const userId = userResult.rows[0].id;

                // Generate reset token
                const resetToken = Helpers.generateRandomToken();
                const expiresAt = Helpers.addHours(new Date(), 1);

                // Save reset token
                await client.query(
                    `INSERT INTO password_resets (user_id, token, expires_at)
                     VALUES ($1, $2, $3)`,
                    [userId, resetToken, expiresAt]
                );

                // In production, send email here
                console.log(`Password reset token for ${email}: ${resetToken}`);
            }

            // Always return success (don't reveal if email exists)
            res.json(
                Helpers.formatResponse(true, 'If your email is registered, you will receive a reset link')
            );

        } catch (err) {
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Reset password
    static async resetPassword(req, res) {
        const client = await db.pool.connect();

        try {
            const { token, newPassword } = req.body;

            // Find valid token
            const tokenResult = await client.query(
                `SELECT user_id FROM password_resets
                 WHERE token = $1 AND expires_at > NOW() AND used = false`,
                [token]
            );

            if (tokenResult.rows.length === 0) {
                return res.status(400).json(
                    Helpers.formatResponse(false, 'Invalid or expired reset token')
                );
            }

            const userId = tokenResult.rows[0].user_id;

            // Hash new password
            const hashedPassword = await Helpers.hashPassword(newPassword);

            await client.query('BEGIN');

            // Update password
            await client.query(
                'UPDATE users SET password_hash = $1 WHERE id = $2',
                [hashedPassword, userId]
            );

            // Mark token as used
            await client.query(
                'UPDATE password_resets SET used = true WHERE token = $1',
                [token]
            );

            // Delete all refresh tokens for security
            await client.query(
                'DELETE FROM refresh_tokens WHERE user_id = $1',
                [userId]
            );

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4)`,
                [userId, 'PASSWORD_RESET', clientInfo.ip_address, clientInfo.user_agent]
            );

            await client.query('COMMIT');

            res.json(
                Helpers.formatResponse(true, 'Password reset successful')
            );

        } catch (err) {
            await client.query('ROLLBACK');
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Change password
    static async changePassword(req, res) {
        const client = await db.pool.connect();

        try {
            const userId = req.user.id;
            const { currentPassword, newPassword } = req.body;

            // Get current password hash
            const result = await client.query(
                'SELECT password_hash FROM users WHERE id = $1',
                [userId]
            );

            const user = result.rows[0];

            // Verify current password
            const isValid = await Helpers.comparePassword(currentPassword, user.password_hash);

            if (!isValid) {
                return res.status(401).json(
                    Helpers.formatResponse(false, 'Current password is incorrect')
                );
            }

            // Hash new password
            const hashedPassword = await Helpers.hashPassword(newPassword);

            await client.query('BEGIN');

            // Update password
            await client.query(
                'UPDATE users SET password_hash = $1 WHERE id = $2',
                [hashedPassword, userId]
            );

            // Delete all refresh tokens for security
            await client.query(
                'DELETE FROM refresh_tokens WHERE user_id = $1',
                [userId]
            );

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4)`,
                [userId, 'PASSWORD_CHANGE', clientInfo.ip_address, clientInfo.user_agent]
            );

            await client.query('COMMIT');

            res.json(
                Helpers.formatResponse(true, 'Password changed successfully')
            );

        } catch (err) {
            await client.query('ROLLBACK');
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Verify email
    static async verifyEmail(req, res) {
        const client = await db.pool.connect();

        try {
            const { token } = req.params;

            // Find valid verification token
            const tokenResult = await client.query(
                `SELECT user_id FROM email_verifications
                 WHERE token = $1 AND expires_at > NOW() AND used = false`,
                [token]
            );

            if (tokenResult.rows.length === 0) {
                return res.status(400).json(
                    Helpers.formatResponse(false, 'Invalid or expired verification token')
                );
            }

            const userId = tokenResult.rows[0].user_id;

            await client.query('BEGIN');

            // Update user as verified
            await client.query(
                'UPDATE users SET is_verified = true WHERE id = $1',
                [userId]
            );

            // Mark token as used
            await client.query(
                'UPDATE email_verifications SET used = true WHERE token = $1',
                [token]
            );

            await client.query('COMMIT');

            res.json(
                Helpers.formatResponse(true, 'Email verified successfully')
            );

        } catch (err) {
            await client.query('ROLLBACK');
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }
}

module.exports = AuthController;