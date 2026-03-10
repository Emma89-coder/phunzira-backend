// utils/db.js
const { Pool } = require('pg');
const config = require('../config/config');

class Database {
    constructor() {
        this.pool = null;
        this.connected = false;
    }

    async connect() {
        try {
            const dbUrl = new URL(config.DATABASE_URL);

            this.pool = new Pool({
                user: decodeURIComponent(dbUrl.username),
                password: decodeURIComponent(dbUrl.password),
                host: dbUrl.hostname,
                port: parseInt(dbUrl.port || '5432'),
                database: dbUrl.pathname.substring(1),
                ssl: config.NODE_ENV === 'production'
                    ? { rejectUnauthorized: false }
                    : false,
                max: 20,
                idleTimeoutMillis: 30000,
                connectionTimeoutMillis: 5000,
            });

            // Test connection
            const client = await this.pool.connect();
            console.log('✅ Connected to PostgreSQL database');

            // Log database name
            const result = await client.query('SELECT current_database()');
            console.log(`📊 Database: ${result.rows[0].current_database}`);

            client.release();
            this.connected = true;

            // Handle pool errors
            this.pool.on('error', (err) => {
                console.error('Unexpected database pool error:', err);
                this.connected = false;
            });

            return this.pool;
        } catch (err) {
            console.error('❌ Database connection failed:', err.message);
            this.connected = false;
            throw err;
        }
    }

    getPool() {
        if (!this.pool || !this.connected) {
            throw new Error('Database not connected');
        }
        return this.pool;
    }

    async query(text, params) {
        const pool = this.getPool();
        const start = Date.now();
        try {
            const res = await pool.query(text, params);
            const duration = Date.now() - start;

            if (config.NODE_ENV === 'development') {
                console.log('📝 Query:', { text, duration, rows: res.rowCount });
            }

            return res;
        } catch (err) {
            console.error('❌ Query error:', err.message);
            throw err;
        }
    }

    async transaction(callback) {
        const pool = this.getPool();
        const client = await pool.connect();

        try {
            await client.query('BEGIN');
            const result = await callback(client);
            await client.query('COMMIT');
            return result;
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    }

    async close() {
        if (this.pool) {
            await this.pool.end();
            this.connected = false;
            console.log('📕 Database connection closed');
        }
    }
}

module.exports = new Database();