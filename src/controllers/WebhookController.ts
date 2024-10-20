import { Request, Response } from 'express';
import { generateWebhookService, processWebhookLeadService } from '../services/webhookService';
import logger from '../config/logger';
import { CustomError } from '../middlewares/errorHandler';

// Controller to generate a webhook for a specific user
export const generateWebhook = async (req: Request, res: Response) => {
    const { userId } = req.body;
    try {
        const webhook = await generateWebhookService(userId);
        res.status(201).json({
            success: true,
            message: 'Webhook created successfully',
            webhook,
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
    const { phoneNumber, firstName, lastName, crmIdentifier } = req.body;
    const verifyToken = req.headers['x-verify-token'] as string;

    try {
        const updatedLead = await processWebhookLeadService(phoneNumber, firstName, lastName, crmIdentifier, verifyToken);
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
