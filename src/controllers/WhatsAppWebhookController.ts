import { Request, Response } from 'express';
import { processWhatsAppResultService } from '../services/whatsappService';
import logger from '../config/logger';

// Controller to process WhatsApp bot result
export const processWhatsAppResult = async (req: Request, res: Response) => {
    const { phoneNumber, userResponse } = req.body;

    try {
        const updatedLead = await processWhatsAppResultService(phoneNumber, userResponse);
        res.status(200).json({
            success: true,
            message: `Lead updated successfully with status: ${updatedLead.status}`,
            lead: updatedLead,
        });
    } catch (error: any) {
        logger.error(`Error processing WhatsApp result: ${error.message}`);
        res.status(error.statusCode || 500).json({
            success: false,
            message: error.message || 'Internal Server Error',
        });
    }
};
