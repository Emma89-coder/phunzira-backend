// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const config = require('./config/config');
const db = require('./utils/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const Helpers = require('./utils/helpers');

const app = express();

// ==================== VALIDATE CONFIG ====================
try {
    config.validateConfig();
} catch (err) {
    console.error('❌ Configuration error:', err.message);
    process.exit(1);
}

// ==================== DATABASE CONNECTION ====================
db.connect().catch(err => {
    console.error('❌ Failed to connect to database');
    if (config.NODE_ENV === 'production') process.exit(1);
});

// ==================== MIDDLEWARE ====================

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
    origin: config.CORS_ORIGINS,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW * 60 * 1000,
    max: config.RATE_LIMIT_MAX,
    message: Helpers.formatResponse(false, 'Too many requests, please try again later'),
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api', limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// ==================== ROUTES ====================

// Health check
app.get('/', (req, res) => {
    res.json({
        name: 'phunzira API',
        version: '1.0.0',
        status: 'running',
        environment: config.NODE_ENV,
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/health',
            auth: '/api/auth',
            users: '/api/users'
        }
    });
});

app.get('/health', async (req, res) => {
    const healthcheck = {
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        status: 'OK',
        environment: config.NODE_ENV,
        database: db.connected ? 'connected' : 'disconnected',
        memory: process.memoryUsage(),
        cpu: process.cpuUsage()
    };

    try {
        await db.query('SELECT 1');
        res.status(200).json(healthcheck);
    } catch (err) {
        healthcheck.status = 'ERROR';
        healthcheck.database = 'disconnected';
        res.status(503).json(healthcheck);
    }
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
    res.status(404).json(
        Helpers.formatResponse(false, 'Route not found', null, { path: req.path })
    );
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);

    res.status(500).json(
        Helpers.formatResponse(
            false,
            config.NODE_ENV === 'production' ? 'Internal server error' : err.message
        )
    );
});

// ==================== START SERVER ====================
const server = app.listen(config.PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${config.PORT}`);
    console.log(`📝 Environment: ${config.NODE_ENV}`);
    console.log(`🔗 Health check: http://localhost:${config.PORT}/health`);
    console.log(`📋 Auth endpoints:`);
    console.log(`   - POST   /api/auth/register`);
    console.log(`   - POST   /api/auth/login`);
    console.log(`   - POST   /api/auth/refresh-token`);
    console.log(`   - POST   /api/auth/logout`);
    console.log(`   - POST   /api/auth/logout-all`);
    console.log(`   - POST   /api/auth/change-password`);
    console.log(`   - POST   /api/auth/forgot-password`);
    console.log(`   - POST   /api/auth/reset-password`);
    console.log(`   - GET    /api/auth/verify-email/:token`);
    console.log(`📋 User endpoints:`);
    console.log(`   - GET    /api/users/profile`);
    console.log(`   - PUT    /api/users/profile`);
    console.log(`   - POST   /api/users/profile/picture`);
    console.log(`   - GET    /api/users/sessions`);
    console.log(`   - DELETE /api/users/sessions/:id`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('📕 SIGTERM received, closing gracefully...');
    await db.close();
    server.close(() => {
        console.log('👋 Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', async () => {
    console.log('📕 SIGINT received, closing gracefully...');
    await db.close();
    server.close(() => {
        console.log('👋 Server closed');
        process.exit(0);
    });
});

module.exports = app;