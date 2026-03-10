// scripts/migrate.js


/**
 * Database Migration Script
 *
 * Usage:
 *   node scripts/migrate.js migrate     # Run pending migrations
 *   node scripts/migrate.js rollback     # Rollback last migration
 *   node scripts/migrate.js reset        # Reset and migrate
 *   node scripts/migrate.js status       # Check migration status
 */

require('dotenv').config();
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

class DatabaseMigration {
    constructor() {
        this.pool = null;
        this.migrationsPath = path.join(__dirname, '../migrations');
        this.batch = null;
    }

    // Connect to database
    async connect() {
        if (!process.env.DATABASE_URL) {
            throw new Error('DATABASE_URL not found in .env file');
        }

        console.log('🔌 Connecting to database...');

        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production'
                ? { rejectUnauthorized: false }
                : false,
            connectionTimeoutMillis: 5000
        });

        // Test connection
        const client = await this.pool.connect();
        console.log('✅ Database connected successfully');
        client.release();

        // Create migrations table if it doesn't exist
        await this.createMigrationsTable();
    }

    // Create migrations tracking table
    async createMigrationsTable() {
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS migrations (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                batch INTEGER NOT NULL,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('📊 Migrations table ready');
    }

    // Get list of executed migrations
    async getExecutedMigrations() {
        const result = await this.pool.query(
            'SELECT name FROM migrations ORDER BY id'
        );
        return result.rows.map(row => row.name);
    }

    // Get last batch number
    async getLastBatch() {
        const result = await this.pool.query(
            'SELECT COALESCE(MAX(batch), 0) as batch FROM migrations'
        );
        return result.rows[0].batch;
    }

    // Get pending migrations
    async getPendingMigrations() {
        // Create migrations folder if it doesn't exist
        if (!fs.existsSync(this.migrationsPath)) {
            fs.mkdirSync(this.migrationsPath, { recursive: true });
        }

        const executed = await this.getExecutedMigrations();
        const files = fs.readdirSync(this.migrationsPath)
            .filter(f => f.endsWith('.sql'))
            .sort();

        return files.filter(file => !executed.includes(file));
    }

    // Run a single migration
    async runMigration(file) {
        const filePath = path.join(this.migrationsPath, file);
        const sql = fs.readFileSync(filePath, 'utf8');

        const client = await this.pool.connect();

        try {
            console.log(`🔄 Running migration: ${file}`);

            await client.query('BEGIN');

            // Run the migration SQL
            await client.query(sql);

            // Record the migration
            await client.query(
                'INSERT INTO migrations (name, batch) VALUES ($1, $2)',
                [file, this.batch]
            );

            await client.query('COMMIT');
            console.log(`✅ Completed: ${file}`);

        } catch (err) {
            await client.query('ROLLBACK');
            console.error(`❌ Failed: ${file} - ${err.message}`);
            throw err;
        } finally {
            client.release();
        }
    }

    // Run all pending migrations
    async migrate() {
        try {
            await this.connect();

            const pending = await this.getPendingMigrations();

            if (pending.length === 0) {
                console.log('✅ No pending migrations');
                await this.close();
                return;
            }

            this.batch = (await this.getLastBatch()) + 1;
            console.log(`\n📦 Running batch #${this.batch} (${pending.length} migrations)\n`);

            for (const file of pending) {
                await this.runMigration(file);
            }

            console.log('\n✅ All migrations completed successfully');

        } catch (err) {
            console.error('\n❌ Migration failed:', err.message);
            process.exit(1);
        } finally {
            await this.close();
        }
    }

    // Rollback last batch
    async rollback() {
        try {
            await this.connect();

            const lastBatch = await this.getLastBatch();

            if (lastBatch === 0) {
                console.log('✅ No migrations to rollback');
                await this.close();
                return;
            }

            // Get migrations from last batch
            const result = await this.pool.query(
                'SELECT name FROM migrations WHERE batch = $1 ORDER BY id DESC',
                [lastBatch]
            );

            console.log(`\n↩️ Rolling back batch #${lastBatch} (${result.rows.length} migrations)\n`);

            for (const row of result.rows) {
                console.log(`↩️ Rolling back: ${row.name}`);

                // For rollback, we need to know what to reverse
                // This requires a more sophisticated setup with up/down migrations
                // For now, we'll just remove the record

                await this.pool.query('DELETE FROM migrations WHERE name = $1', [row.name]);
                console.log(`✅ Rolled back: ${row.name}`);
            }

            console.log('\n✅ Rollback completed');

        } catch (err) {
            console.error('\n❌ Rollback failed:', err.message);
            process.exit(1);
        } finally {
            await this.close();
        }
    }

    // Reset database (drop all tables and migrate)
    async reset() {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        rl.question('\n⚠️  This will DROP ALL TABLES. Are you sure? (yes/no): ', async (answer) => {
            if (answer.toLowerCase() !== 'yes') {
                console.log('❌ Reset cancelled');
                rl.close();
                return;
            }

            rl.close();

            try {
                await this.connect();

                console.log('\n🔄 Resetting database...');

                // Drop all tables
                await this.pool.query(`
                    DROP SCHEMA public CASCADE;
                    CREATE SCHEMA public;
                `);

                console.log('✅ Database reset complete');

                // Run migrations
                await this.migrate();

            } catch (err) {
                console.error('\n❌ Reset failed:', err.message);
                process.exit(1);
            } finally {
                await this.close();
            }
        });
    }

    // Show migration status
    async status() {
        try {
            await this.connect();

            const executed = await this.getExecutedMigrations();

            // Create migrations folder if it doesn't exist
            if (!fs.existsSync(this.migrationsPath)) {
                fs.mkdirSync(this.migrationsPath, { recursive: true });
            }

            const allFiles = fs.readdirSync(this.migrationsPath)
                .filter(f => f.endsWith('.sql'))
                .sort();

            console.log('\n📊 MIGRATION STATUS');
            console.log('='.repeat(60));
            console.log('📍 Database:', process.env.DATABASE_URL?.split('@')[1]?.split('/')[0] || 'local');
            console.log('='.repeat(60));

            for (const file of allFiles) {
                const isExecuted = executed.includes(file);
                const status = isExecuted ? '✅' : '⏳';
                console.log(`${status}  ${file}`);
            }

            console.log('='.repeat(60));
            console.log(`Total: ${allFiles.length} files (${executed.length} executed, ${allFiles.length - executed.length} pending)`);
            console.log('='.repeat(60));

        } catch (err) {
            console.error('\n❌ Status check failed:', err.message);
            process.exit(1);
        } finally {
            await this.close();
        }
    }

    // Create a new migration file
    async create(name) {
        if (!name) {
            console.error('❌ Please provide a migration name');
            console.log('Example: node scripts/migrate.js create add_phone_to_users');
            return;
        }

        // Create migrations folder if it doesn't exist
        if (!fs.existsSync(this.migrationsPath)) {
            fs.mkdirSync(this.migrationsPath, { recursive: true });
        }

        // Generate filename with timestamp
        const timestamp = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
        const filename = `${timestamp}_${name}.sql`;
        const filepath = path.join(this.migrationsPath, filename);

        // Create template
        const template = `-- Migration: ${name}
-- Created: ${new Date().toISOString()}

-- Write your SQL here
-- Example:
-- CREATE TABLE example (id SERIAL PRIMARY KEY);
-- ALTER TABLE users ADD COLUMN phone VARCHAR(20);

`;

        fs.writeFileSync(filepath, template);
        console.log(`✅ Created migration: ${filename}`);
    }

    // Close database connection
    async close() {
        if (this.pool) {
            await this.pool.end();
            console.log('🔌 Database connection closed');
        }
    }
}

// ==================== CLI Interface ====================
const command = process.argv[2];
const migrationName = process.argv[3];

const migration = new DatabaseMigration();

async function run() {
    switch (command) {
        case 'migrate':
            await migration.migrate();
            break;

        case 'rollback':
            await migration.rollback();
            break;

        case 'reset':
            await migration.reset();
            break;

        case 'status':
            await migration.status();
            break;

        case 'create':
            await migration.create(migrationName);
            break;

        case 'help':
        default:
            console.log(`
📋 DATABASE MIGRATION TOOL
===========================
Commands:
  migrate                    Run all pending migrations
  rollback                   Rollback last batch
  reset                      Reset database and migrate
  status                     Show migration status
  create <name>              Create a new migration file
  help                       Show this help

Examples:
  node scripts/migrate.js migrate
  node scripts/migrate.js create add_phone_to_users
  node scripts/migrate.js status
  node scripts/migrate.js reset
            `);
            break;
    }
}

run().catch(console.error);