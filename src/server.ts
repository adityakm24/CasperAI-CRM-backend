import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import cluster from 'cluster';
import os from 'os';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import compression from 'compression';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { config } from './config/env';
import logger from './config/logger';
import authRoutes from './routes/authRoutes';
import { rateLimiter } from './middlewares/rateLimiter';
import requestLogger from './middlewares/requestLogger';
import { errorHandler } from './middlewares/errorHandler';
import webhookRoutes from './routes/WebhookRoutes';
import whatsappWebhookRoutes from './routes/WebhookRoutes';
import { generateKeys } from './Keys/generateKeys';
import leadRoutes from './routes/leadRoutes';  // Add this line


dotenv.config();

const setupMiddlewares = (app: express.Application) => {
    app.use(helmet());
    app.use(compression());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    app.use(
        cors({
            origin: ['https://backend.casperai.co', 'https://casper-ai-72di.vercel.app', 'http://localhost:3000','http://localhost:5173'],
            credentials: true,
            methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
            optionsSuccessStatus: 204,
        })
    );

    app.use(cookieParser());
    app.use(rateLimiter);
    app.use(requestLogger);
};

const setupSocketIO = (server: http.Server) => {
    const io = new SocketIOServer(server, {
        cors: {
            origin: ['https://backend.casperai.co', 'https://casper-ai-72di.vercel.app', 'http://localhost:3000'],
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'],
            credentials: true,
        },
    });

    io.on('connection', (socket) => {
        logger.info(`WebSocket client connected: ${socket.id}`);

        socket.on('message', (message) => {
            logger.info(`Message from ${socket.id}: ${message}`);
            socket.emit('response', `Message received: ${message}`);
        });

        socket.on('disconnect', () => {
            logger.info(`WebSocket client disconnected: ${socket.id}`);
        });
    });

    return io;
};

const setupGracefulShutdown = () => {
    const shutdown = async () => {
        logger.info('Shutting down gracefully...');
        await mongoose.connection.close();
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
};

const startServer = (app: express.Application, server: http.Server, port: number) => {
    const portNumber = Number(port);
    if (config.nodeEnv === 'production') {
        if (cluster.isPrimary) {
            logger.info(`Master ${process.pid} is running`);

            os.cpus().forEach(() => cluster.fork());

            cluster.on('exit', (worker) => {
                logger.warn(`Worker ${worker.process.pid} died. Restarting...`);
                cluster.fork();
            });
        } else {
            server.listen(port, () => {
                logger.info(`Worker ${process.pid} started on port ${port}`);
            });
        }
    } else {
        server.listen(port, () => {
            logger.info(`Server running on port ${port} in ${config.nodeEnv} mode`);
        });
    }
};

const initializeServer = async () => {
    generateKeys();

    const app = express();
    const server = http.createServer(app);

    setupMiddlewares(app);

    setupSocketIO(server);

    app.use('/auth', authRoutes);
    app.use('/webhook', webhookRoutes); 
    app.use('/whatsapp', whatsappWebhookRoutes);  
    app.use('/leads', leadRoutes);  // Use the new lead routes
    app.get('/health', (req, res) => res.status(200).json({ status: 'OK' }));

    app.use(errorHandler);

    try {
        await mongoose.connect(config.mongoUri);
        logger.info('Connected to MongoDB');
        startServer(app, server, config.port);
    } catch (error: any) {
        logger.error('Failed to connect to MongoDB', { error: error.message });
    }

    setupGracefulShutdown();
};

initializeServer();
