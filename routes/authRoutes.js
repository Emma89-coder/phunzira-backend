// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const AuthMiddleware = require('../middleware/auth');
const ValidationMiddleware = require('../middleware/validation');

// Public routes
router.post(
    '/register',
    ValidationMiddleware.registerRules,
    ValidationMiddleware.validate,
    ValidationMiddleware.checkEmailNotInUse,
    ValidationMiddleware.checkUsernameNotInUse,
    AuthController.register
);

router.post(
    '/login',
    AuthMiddleware.authRateLimiter,
    ValidationMiddleware.loginRules,
    ValidationMiddleware.validate,
    AuthController.login
);

router.post(
    '/refresh-token',
    ValidationMiddleware.refreshTokenRules,
    ValidationMiddleware.validate,
    AuthMiddleware.authenticateRefreshToken,
    AuthController.refreshToken
);

router.post(
    '/forgot-password',
    AuthMiddleware.authRateLimiter,
    ValidationMiddleware.forgotPasswordRules,
    ValidationMiddleware.validate,
    AuthController.forgotPassword
);

router.post(
    '/reset-password',
    AuthMiddleware.authRateLimiter,
    ValidationMiddleware.resetPasswordRules,
    ValidationMiddleware.validate,
    AuthController.resetPassword
);

router.get('/verify-email/:token', AuthController.verifyEmail);

// Protected routes
router.use(AuthMiddleware.authenticateToken);

router.post('/logout', AuthController.logout);
router.post('/logout-all', AuthController.logoutAll);
router.post(
    '/change-password',
    ValidationMiddleware.changePasswordRules,
    ValidationMiddleware.validate,
    AuthController.changePassword
);

module.exports = router;