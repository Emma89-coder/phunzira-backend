// middleware/validation.js
const { body, validationResult } = require('express-validator');
const Helpers = require('../utils/helpers');

class ValidationMiddleware {
    // Validation rules
    static registerRules = [
        body('username')
            .trim()
            .isLength({ min: 3, max: 50 })
            .withMessage('Username must be 3-50 characters')
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username can only contain letters, numbers, and underscores'),

        body('email')
            .trim()
            .isEmail()
            .withMessage('Must be a valid email address')
            .normalizeEmail(),

        body('password')
            .isLength({ min: 6 })
            .withMessage('Password must be at least 6 characters')
            .matches(/^(?=.*[A-Za-z])(?=.*\d)/)
            .withMessage('Password must contain at least one letter and one number'),

        body('first_name')
            .optional()
            .trim()
            .isLength({ max: 50 })
            .withMessage('First name cannot exceed 50 characters'),

        body('last_name')
            .optional()
            .trim()
            .isLength({ max: 50 })
            .withMessage('Last name cannot exceed 50 characters'),

        body('phone')
            .optional()
            .trim()
            .custom(value => !value || Helpers.isValidPhone(value))
            .withMessage('Invalid phone number format')
    ];

    static loginRules = [
        body('email')
            .isEmail()
            .withMessage('Valid email required')
            .normalizeEmail(),

        body('password')
            .notEmpty()
            .withMessage('Password is required')
    ];

    static refreshTokenRules = [
        body('refreshToken')
            .notEmpty()
            .withMessage('Refresh token required')
    ];

    static changePasswordRules = [
        body('currentPassword')
            .notEmpty()
            .withMessage('Current password required'),

        body('newPassword')
            .isLength({ min: 6 })
            .withMessage('New password must be at least 6 characters')
            .matches(/^(?=.*[A-Za-z])(?=.*\d)/)
            .withMessage('Password must contain at least one letter and one number')
    ];

    static forgotPasswordRules = [
        body('email')
            .isEmail()
            .withMessage('Valid email required')
            .normalizeEmail()
    ];

    static resetPasswordRules = [
        body('token')
            .notEmpty()
            .withMessage('Reset token required'),

        body('newPassword')
            .isLength({ min: 6 })
            .withMessage('Password must be at least 6 characters')
            .matches(/^(?=.*[A-Za-z])(?=.*\d)/)
            .withMessage('Password must contain at least one letter and one number')
    ];

    static updateProfileRules = [
        body('first_name')
            .optional()
            .trim()
            .isLength({ max: 50 }),

        body('last_name')
            .optional()
            .trim()
            .isLength({ max: 50 }),

        body('phone')
            .optional()
            .trim()
            .custom(value => !value || Helpers.isValidPhone(value))
    ];

    // Validate request
    static validate(req, res, next) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array().map(err => ({
                    field: err.path,
                    message: err.msg
                }))
            });
        }
        next();
    }

    // Custom validators
    static async checkEmailNotInUse(req, res, next) {
        const db = require('../utils/db');
        const { email } = req.body;

        if (!email) return next();

        try {
            const result = await db.query(
                'SELECT id FROM users WHERE email = $1',
                [email]
            );

            if (result.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Email already in use'
                });
            }
            next();
        } catch (err) {
            next(err);
        }
    }

    static async checkUsernameNotInUse(req, res, next) {
        const db = require('../utils/db');
        const { username } = req.body;

        if (!username) return next();

        try {
            const result = await db.query(
                'SELECT id FROM users WHERE username = $1',
                [username]
            );

            if (result.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Username already taken'
                });
            }
            next();
        } catch (err) {
            next(err);
        }
    }
}

module.exports = ValidationMiddleware;