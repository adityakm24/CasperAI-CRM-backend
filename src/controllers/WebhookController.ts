import { Request, Response } from 'express';
import Lead from '../models/Leads';
import { randomBytes } from 'crypto';
import Webhook from '../models/Webhook';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';

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
        const verifyToken = randomBytes(20).toString('hex');

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
    const { phoneNumber, firstName, lastName, crmIdentifier } = req.body; // crmIdentifier is optional
    const verifyToken = req.headers['x-verify-token']; // Token sent via headers

    try {
        // Check if the webhook with the given verify token exists
        const userWebhook = await Webhook.findOne({ verifyToken });

        if (!userWebhook) {
            logger.warn('Invalid webhook request, token not found');
            throw new CustomError('Invalid verify token', 403);
        }

        // Validate required fields
        if (!phoneNumber || !firstName || !lastName) {
            logger.warn('Missing required fields in webhook payload');
            throw new CustomError('Missing required fields: phoneNumber, firstName, or lastName', 400);
        }

        // Upsert (update or insert) the lead based on the phone number and userId
        const updatedLead = await Lead.findOneAndUpdate(
            { phoneNumber, userId: userWebhook.userId }, // Find the lead by phone number and user
            {
                phoneNumber,
                firstName,
                lastName,
                crmIdentifier: crmIdentifier || '',  // Default to an empty string if not provided
                status: 'fresh',  // Default status, can be updated later
                userId: userWebhook.userId,
                tag: 'CRM Lead',  // Tag to indicate the lead came from CRM
            },
            { new: true, upsert: true } // Create a new lead if it doesn't exist
        );

        logger.info(`Lead ${updatedLead ? 'updated' : 'created'} successfully for user: ${userWebhook.userId}`);

        res.status(201).json({
            success: true,
            message: `Lead ${updatedLead ? 'updated' : 'created'} successfully`,
            lead: updatedLead,
        });
    } catch (error: any) {
        logger.error(`Error processing webhook: ${error.message}`);
        res.status(error.statusCode || 500).json({
            success: false,
            message: error.message || 'Internal Server Error',
        });
    }
};
