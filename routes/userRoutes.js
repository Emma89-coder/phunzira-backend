// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const UserController = require('../controllers/userController');
const AuthMiddleware = require('../middleware/auth');
const ValidationMiddleware = require('../middleware/validation');

// All routes require authentication
router.use(AuthMiddleware.authenticateToken);

// Profile routes
router.get('/profile', UserController.getProfile);
router.put(
    '/profile',
    ValidationMiddleware.updateProfileRules,
    ValidationMiddleware.validate,
    UserController.updateProfile
);
router.post('/profile/picture', UserController.uploadProfilePicture);

// Session routes
router.get('/sessions', UserController.getUserSessions);
router.delete('/sessions/:id', UserController.revokeSession);

// Admin only routes
router.get('/admin/users', AuthMiddleware.isAdmin, UserController.getAllUsers);
router.get('/admin/users/:id', AuthMiddleware.isAdmin, UserController.getUserById);
router.put('/admin/users/:id/deactivate', AuthMiddleware.isAdmin, UserController.deactivateUser);
router.put('/admin/users/:id/activate', AuthMiddleware.isAdmin, UserController.activateUser);
router.delete('/admin/users/:id', AuthMiddleware.isAdmin, UserController.deleteUser);

module.exports = router;