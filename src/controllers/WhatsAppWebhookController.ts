import { Request, Response, NextFunction } from 'express';
import { processWhatsAppResultService } from '../services/whatsappService';
import logger from '../config/logger';
import { sendSuccessResponse, sendInternalServerErrorResponse } from '../utils/responseHandler'; 


export const processWhatsAppResult = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { phoneNumber, userResponse } = req.body;

        const updatedLead = await processWhatsAppResultService(phoneNumber, userResponse);

        logger.info(`Lead updated successfully for phone number: ${phoneNumber} with status: ${updatedLead.status}`);

        return sendSuccessResponse(res, { lead: updatedLead }, `Lead updated successfully with status: ${updatedLead.status}`);
    } catch (error) {
        logger.error('Error processing WhatsApp result', { error });
        return sendInternalServerErrorResponse(res, 'Error processing WhatsApp result');
    }
};
