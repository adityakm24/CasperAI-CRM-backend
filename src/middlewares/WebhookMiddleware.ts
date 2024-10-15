import { Request, Response, NextFunction } from 'express';
import Webhook from '../models/Webhook';
import logger from '../config/logger';
import { CustomError } from './errorHandler';

// Middleware to validate verifyToken in the headers
export const validateWebhookToken = async (req: Request, res: Response, next: NextFunction) => {
    const verifyToken = req.headers['x-verify-token'];

    if (!verifyToken) {
        logger.warn('Missing verify token in request headers');
        return res.status(400).json({ success: false, message: 'Verify token is required' });
    }

    try {
        const userWebhook = await Webhook.findOne({ verifyToken });

        if (!userWebhook) {
            logger.warn('Invalid verify token provided');
            throw new CustomError('Invalid verify token', 403);
        }

        req.user = { userId: userWebhook.userId }; // Attach user info to req object
        next();
    } catch (error: any) {
        logger.error('Error validating webhook token', { error: error.message });
        res.status(error.statusCode || 500).json({
            success: false,
            message: error.message || 'Internal Server Error',
        });
    }
};
