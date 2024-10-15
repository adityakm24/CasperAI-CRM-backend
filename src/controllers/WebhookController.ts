import { Request, Response } from 'express';
import Lead from '../models/Leads';
import Webhook from '../models/Webhook';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';
import crypto from 'crypto';

// Controller to generate a webhook for a specific user
export const generateWebhook = async (req: Request, res: Response) => {
    const { userId } = req.body;

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
};

// Controller to process incoming leads from the CRM webhook
export const processWebhookLead = async (req: Request, res: Response) => {
    const { phoneNumber, firstName, lastName, crmIdentifier } = req.body; // Ensure crmIdentifier is included
    const verifyToken = req.headers['x-verify-token']; // Token sent via headers

    try {
        // Check if the webhook with the given verify token exists
        const userWebhook = await Webhook.findOne({ verifyToken });

        if (!userWebhook) {
            logger.warn('Invalid webhook request, token not found');
            throw new CustomError('Invalid verify token', 403);
        }

        // Validate required fields
        if (!phoneNumber || !firstName || !lastName || !crmIdentifier) {
            logger.warn('Missing required fields in webhook payload');
            throw new CustomError('Missing required fields: phoneNumber, firstName, lastName, or crmIdentifier', 400);
        }

        // Create a new lead for the user associated with the webhook
        const newLead = new Lead({
            phoneNumber,
            firstName,
            lastName,
            crmIdentifier,  // Ensure crmIdentifier is passed
            status: 'fresh', // Default status
            userId: userWebhook.userId, // Link the lead to the correct user
            tag: 'CRM Lead', // Tag to indicate the lead came from CRM
        });

        await newLead.save();

        logger.info(`Lead created successfully for user: ${userWebhook.userId}`);

        res.status(201).json({
            success: true,
            message: 'Lead created successfully',
            lead: newLead,
        });
    } catch (error: any) {
        logger.error(`Error processing webhook: ${error.message}`);
        res.status(error.statusCode || 500).json({
            success: false,
            message: error.message || 'Internal Server Error',
        });
    }
};
