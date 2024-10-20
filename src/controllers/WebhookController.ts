import { Request, Response } from 'express';
import { generateWebhookService, processWebhookLeadService } from '../services/webhookService';
import logger from '../config/logger';
import { httpHandler } from '../utils/httpHandler';

// Controller to generate a webhook for a specific user
export const generateWebhook = httpHandler(async (req: Request, res: Response) => {
    const { userId } = req.body;
    const webhook = await generateWebhookService(userId);

    logger.info(`Webhook created successfully for user: ${userId}`);

    res.status(201).json({
        success: true,
        message: 'Webhook created successfully',
        webhook,
    });
});

// Controller to process incoming leads from the CRM webhook
export const processWebhookLead = httpHandler(async (req: Request, res: Response) => {
    const { phoneNumber, firstName, lastName, crmIdentifier } = req.body;
    const verifyToken = req.headers['x-verify-token'] as string;

    const updatedLead = await processWebhookLeadService(phoneNumber, firstName, lastName, crmIdentifier, verifyToken);

    logger.info(`Lead ${updatedLead ? 'updated' : 'created'} successfully`);

    res.status(201).json({
        success: true,
        message: `Lead ${updatedLead ? 'updated' : 'created'} successfully`,
        lead: updatedLead,
    });
});
