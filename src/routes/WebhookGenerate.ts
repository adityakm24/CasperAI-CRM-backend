import express, { Request, Response } from 'express';
import Webhook from '../models/Webhook';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';
import crypto from 'crypto';

// Create the webhook router
const router = express.Router();

// Route to generate a webhook for a specific user
router.post('/webhook/generate', async (req: Request, res: Response) => {
    const { userId } = req.body; // Assuming userId comes from a logged-in session or request body

    try {
        // Check if the user already has a webhook
        const existingWebhook = await Webhook.findOne({ userId });
        if (existingWebhook) {
            logger.warn(`Webhook already exists for user: ${userId}`);
            throw new CustomError('Webhook already exists for this user', 409);
        }

        // Generate a unique verify token
        const verifyToken = crypto.randomBytes(20).toString('hex');

        // Create and save the webhook
        const newWebhook = new Webhook({
            userId,
            verifyToken,
        });

        await newWebhook.save();

        logger.info(`Webhook created successfully for user: ${userId}`);

        res.status(201).json({
            success: true,
            message: 'Webhook created successfully',
            webhook: {
                url: `/webhook`,
                verifyToken,
            },
        });
    } catch (error: any) {
        logger.error(`Error creating webhook for user: ${userId}`, { error: error.message });
        res.status(error.statusCode || 500).json({
            success: false,
            message: error.message || 'Internal Server Error',
        });
    }
});

export default router;
