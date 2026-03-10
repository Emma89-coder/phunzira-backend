// controllers/userController.js
const db = require('../utils/db');
const Helpers = require('../utils/helpers');

class UserController {
    // Get current user profile
    static async getProfile(req, res) {
        try {
            const result = await db.query(
                `SELECT id, uuid, username, email, first_name, last_name, phone,
                        role, profile_picture, is_active, is_verified, last_login, created_at
                 FROM users
                 WHERE id = $1`,
                [req.user.id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json(
                    Helpers.formatResponse(false, 'User not found')
                );
            }

            res.json({
                success: true,
                data: { user: result.rows[0] }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        }
    }

    // Update user profile
    static async updateProfile(req, res) {
        const client = await db.pool.connect();

        try {
            const userId = req.user.id;
            const { first_name, last_name, phone } = req.body;

            const result = await client.query(
                `UPDATE users
                 SET first_name = COALESCE($1, first_name),
                     last_name = COALESCE($2, last_name),
                     phone = COALESCE($3, phone),
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = $4
                 RETURNING id, uuid, username, email, first_name, last_name, phone, role, profile_picture`,
                [first_name, last_name, phone, userId]
            );

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, old_data, new_data, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [
                    userId,
                    'PROFILE_UPDATED',
                    'users',
                    userId,
                    JSON.stringify({}),
                    JSON.stringify(result.rows[0]),
                    clientInfo.ip_address,
                    clientInfo.user_agent
                ]
            );

            res.json({
                success: true,
                message: 'Profile updated successfully',
                data: { user: result.rows[0] }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Upload profile picture
    static async uploadProfilePicture(req, res) {
        try {
            const userId = req.user.id;
            const { profile_picture } = req.body;

            // In production, you'd handle file upload here
            // For now, we'll just update the URL

            await db.query(
                'UPDATE users SET profile_picture = $1 WHERE id = $2',
                [profile_picture, userId]
            );

            res.json({
                success: true,
                message: 'Profile picture updated',
                data: { profile_picture }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        }
    }

    // Get user by ID (admin only)
    static async getUserById(req, res) {
        try {
            const userId = parseInt(req.params.id);

            const result = await db.query(
                `SELECT id, uuid, username, email, first_name, last_name, phone,
                        role, profile_picture, is_active, is_verified, last_login, created_at
                 FROM users
                 WHERE id = $1`,
                [userId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json(
                    Helpers.formatResponse(false, 'User not found')
                );
            }

            res.json({
                success: true,
                data: { user: result.rows[0] }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        }
    }

    // Get all users (admin only)
    static async getAllUsers(req, res) {
        try {
            const { page = 1, limit = 10, search, role } = req.query;
            const pagination = Helpers.getPaginationParams(page, limit);

            let query = `
                SELECT id, uuid, username, email, first_name, last_name, phone,
                       role, is_active, is_verified, last_login, created_at
                FROM users
                WHERE 1=1
            `;
            const params = [];
            let paramIndex = 1;

            if (search) {
                query += ` AND (username ILIKE $${paramIndex} OR email ILIKE $${paramIndex})`;
                params.push(`%${search}%`);
                paramIndex++;
            }

            if (role) {
                query += ` AND role = $${paramIndex}`;
                params.push(role);
                paramIndex++;
            }

            query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
            params.push(pagination.limit, pagination.offset);

            const result = await db.query(query, params);

            // Get total count
            const countResult = await db.query(
                'SELECT COUNT(*) FROM users'
            );

            res.json({
                success: true,
                data: {
                    users: result.rows,
                    pagination: {
                        page: pagination.page,
                        limit: pagination.limit,
                        total: parseInt(countResult.rows[0].count),
                        pages: Math.ceil(countResult.rows[0].count / pagination.limit)
                    }
                }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        }
    }

    // Deactivate user (admin only)
    static async deactivateUser(req, res) {
        const client = await db.pool.connect();

        try {
            const userId = parseInt(req.params.id);

            // Check if user exists
            const userResult = await client.query(
                'SELECT id, username FROM users WHERE id = $1',
                [userId]
            );

            if (userResult.rows.length === 0) {
                return res.status(404).json(
                    Helpers.formatResponse(false, 'User not found')
                );
            }

            await client.query('BEGIN');

            // Deactivate user
            await client.query(
                'UPDATE users SET is_active = false WHERE id = $1',
                [userId]
            );

            // Delete all refresh tokens
            await client.query(
                'DELETE FROM refresh_tokens WHERE user_id = $1',
                [userId]
            );

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [req.user.id, 'USER_DEACTIVATED', 'users', userId, clientInfo.ip_address, clientInfo.user_agent]
            );

            await client.query('COMMIT');

            res.json({
                success: true,
                message: 'User deactivated successfully'
            });

        } catch (err) {
            await client.query('ROLLBACK');
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Activate user (admin only)
    static async activateUser(req, res) {
        try {
            const userId = parseInt(req.params.id);

            const result = await db.query(
                'UPDATE users SET is_active = true WHERE id = $1 RETURNING id',
                [userId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json(
                    Helpers.formatResponse(false, 'User not found')
                );
            }

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await db.query(
                `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [req.user.id, 'USER_ACTIVATED', 'users', userId, clientInfo.ip_address, clientInfo.user_agent]
            );

            res.json({
                success: true,
                message: 'User activated successfully'
            });

        } catch (err) {
            Helpers.handleError(res, err);
        }
    }

    // Delete user (admin only)
    static async deleteUser(req, res) {
        const client = await db.pool.connect();

        try {
            const userId = parseInt(req.params.id);

            await client.query('BEGIN');

            // Delete related records first (cascade should handle this, but being explicit)
            await client.query('DELETE FROM refresh_tokens WHERE user_id = $1', [userId]);
            await client.query('DELETE FROM password_resets WHERE user_id = $1', [userId]);
            await client.query('DELETE FROM email_verifications WHERE user_id = $1', [userId]);

            // Delete user
            const result = await client.query(
                'DELETE FROM users WHERE id = $1 RETURNING id, username, email',
                [userId]
            );

            if (result.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json(
                    Helpers.formatResponse(false, 'User not found')
                );
            }

            // Log action
            const clientInfo = Helpers.getClientInfo(req);
            await client.query(
                `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, old_data, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [
                    req.user.id,
                    'USER_DELETED',
                    'users',
                    userId,
                    JSON.stringify(result.rows[0]),
                    clientInfo.ip_address,
                    clientInfo.user_agent
                ]
            );

            await client.query('COMMIT');

            res.json({
                success: true,
                message: 'User deleted successfully'
            });

        } catch (err) {
            await client.query('ROLLBACK');
            Helpers.handleError(res, err);
        } finally {
            client.release();
        }
    }

    // Get user sessions
    static async getUserSessions(req, res) {
        try {
            const userId = req.user.id;

            const result = await db.query(
                `SELECT id, device_info, ip_address, created_at, expires_at
                 FROM user_sessions
                 WHERE user_id = $1 AND expires_at > NOW()
                 ORDER BY created_at DESC`,
                [userId]
            );

            res.json({
                success: true,
                data: { sessions: result.rows }
            });

        } catch (err) {
            Helpers.handleError(res, err);
        }
    }

    // Revoke session
    static async revokeSession(req, res) {
        try {
            const sessionId = parseInt(req.params.id);
            const userId = req.user.id;

            const result = await db.query(
                'DELETE FROM user_sessions WHERE id = $1 AND user_id = $2 RETURNING id',
                [sessionId, userId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json(
                    Helpers.formatResponse(false, 'Session not found')
                );
            }

            res.json({
                success: true,
                message: 'Session revoked successfully'
            });

        } catch (err) {
            Helpers.handleError(res, err);
        }
    }
}

module.exports = UserController;