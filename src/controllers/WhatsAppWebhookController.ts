import { Request, Response } from 'express';
import { processWhatsAppResultService } from '../services/whatsappService';
import logger from '../config/logger';
import { httpHandler } from '../utils/httpHandler';

// Controller to process WhatsApp bot result
export const processWhatsAppResult = httpHandler(async (req: Request, res: Response) => {
    const { phoneNumber, userResponse } = req.body;

    const updatedLead = await processWhatsAppResultService(phoneNumber, userResponse);

    logger.info(`Lead updated successfully for phone number: ${phoneNumber} with status: ${updatedLead.status}`);

    res.status(200).json({
        success: true,
        message: `Lead updated successfully with status: ${updatedLead.status}`,
        lead: updatedLead,
    });
});
