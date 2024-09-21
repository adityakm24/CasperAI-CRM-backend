import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import passport from 'passport';
import authRoutes from './routes/authRoutes';
import { errorHandler } from './middlewares/errorHandler';
import { generateKeys } from './Keys/generateKeys';
import { config } from './config/env';
import logger from './config/logger';
import './config/passportConfig';
import cluster from 'cluster';
import os from 'os';
import { rateLimiter } from './middlewares/rateLimiter';
import compression from 'compression';
import requestLogger from './middlewares/requestLogger';
// import { helmetConfig } from './config/helmetConfig';;
// import stripeRoutes from './routes/stripeRoutes';



dotenv.config();
generateKeys();


const PORT = config.port;


if (process.env.NODE_ENV === 'production') {
    if (cluster.isPrimary) {
        logger.info(`Master ${process.pid} is running`);
        for (let i = 0; i < os.cpus().length; i++) {
            cluster.fork();
        }
        cluster.on('exit', (worker, code, signal) => {
            logger.info(`Worker ${worker.process.pid} died. Restarting...`);
            cluster.fork();
        });
    }
} else {
    logger.info(`Skipping cluster mode in development`);
}

const app = express();

app.use(compression());

app.use(express.json());
app.use(cors({
    origin: ['https://backend.casperai.co', 'https://casper-ai-72di.vercel.app', 'http://localhost:3000', 'https://api.vapi.ai/call', 'https://api.vapi.ai', 'https://app.casperai.co'],
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204
}));


app.use(rateLimiter);

app.use(requestLogger);

app.use(passport.initialize());




app.use('/auth', authRoutes);


app.get('/health', (req, res) => {
    res.status(200).send({ status: 'OK' });
});


app.use(errorHandler);


mongoose
    .connect(config.mongoUri)
    .then(() => {
        logger.info('Connected to MongoDB');
        if (process.env.NODE_ENV !== 'test') {
            app.listen(PORT, () => {
                logger.info(`Server is running on port ${PORT}`);
            });
        }
    })
    .catch((err: any) => {
        logger.error('Failed to connect to MongoDB', { error: err.message });
    });

process.on('SIGINT', async () => {
    logger.info('SIGINT received. Shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

export default app;