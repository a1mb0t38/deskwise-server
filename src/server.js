import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import { toNodeHandler } from 'better-auth/node';
import { auth } from './auth.js';
import { VULN_MODES } from './config/vulnModes.js';
import { seed } from '../scripts/seed.js';

import profileRoutes from './routes/profile.js';
import ticketRoutes from './routes/tickets.js';
import flagRoutes from './routes/flags.js';
import adminRoutes from './routes/admin.js';
import debugRoutes from './routes/debug.js';
import systemRoutes from './routes/system.js';
import authExtRoutes from './routes/auth-ext.js';

const app = express();

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Better Auth handler mounted BEFORE express.json()
app.all('/api/auth/*splat', toNodeHandler(auth));

app.use(express.json());

// Mounted Routes
app.use('/api/profile', profileRoutes);
app.use('/api/tickets', ticketRoutes);
app.use('/api/flags', flagRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/debug', debugRoutes);
app.use('/api/system', systemRoutes);
app.use('/api/auth-ext', authExtRoutes);

app.get('/', (req, res) => {
    res.send("DeskWise Vulnerable Server is running");
});

/**
 * Global Error Handling Middleware
 *
 * VULNERABILITY (A02 — Security Misconfiguration, CWE-209):
 * In vulnerable mode, unhandled server errors return verbose internal stack traces
 * and error details to the client instead of generic 500 error messages.
 */
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);

    if (VULN_MODES.MISCONFIG_DEBUG === "vulnerable") {
        return res.status(500).json({
            error: err.message,
            stack: err.stack,
            type: err.constructor.name,
            note: "Verbose error details returned due to MISCONFIG_DEBUG mode."
        });
    }

    return res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT || 5000;

async function startServer(){
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("Connected to MongoDB");

        // Automatically seed database on first run if empty
        await seed(false);

        app.listen(PORT, ()=>{
            console.log(`Server is running on port ${PORT}`);
        });
    } catch(err) {
        console.error("Failed to connect to MongoDB:", err.message);
        process.exit(1);
    }
}

startServer();