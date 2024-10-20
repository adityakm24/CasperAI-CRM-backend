import { Request, Response, NextFunction } from 'express';
import { generateWebhookService, processWebhookLeadService } from '../services/webhookService';
import logger from '../config/logger';
import { sendCreatedResponse, sendSuccessResponse, sendInternalServerErrorResponse } from '../utils/responseHandler'; 


export const generateWebhook = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { userId } = req.body;
        const webhook = await generateWebhookService(userId);

        logger.info(`Webhook created successfully for user: ${userId}`);

        return sendCreatedResponse(res, { webhook }, 'Webhook created successfully');
    } catch (error) {
        logger.error('Error creating webhook', { error });
        return sendInternalServerErrorResponse(res, 'Error creating webhook');
    }
};

export const processWebhookLead = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { phoneNumber, firstName, lastName, crmIdentifier } = req.body;
        const verifyToken = req.headers['x-verify-token'] as string;

        const updatedLead = await processWebhookLeadService(phoneNumber, firstName, lastName, crmIdentifier, verifyToken);

        logger.info(`Lead ${updatedLead ? 'updated' : 'created'} successfully`);

        return sendCreatedResponse(res, { lead: updatedLead }, `Lead ${updatedLead ? 'updated' : 'created'} successfully`);
    } catch (error) {
        logger.error('Error processing webhook lead', { error });
        return sendInternalServerErrorResponse(res, 'Error processing webhook lead');
    }
};
