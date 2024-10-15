import { Request, Response } from 'express';
import Lead from '../models/Leads';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';

// Controller to process WhatsApp bot result
export const processWhatsAppResult = async (req: Request, res: Response) => {
    const { phoneNumber, userResponse } = req.body; // Assuming WhatsApp bot sends these fields

    try {
        // Validate required fields
        if (!phoneNumber || !userResponse) {
            logger.warn('Missing required fields in WhatsApp bot payload');
            throw new CustomError('Missing required fields: phoneNumber or userResponse', 400);
        }

        // Find the lead by phone number
        const lead = await Lead.findOne({ phoneNumber });
        if (!lead) {
            logger.warn(`No lead found with phone number: ${phoneNumber}`);
            throw new CustomError('No lead found with this phone number', 404);
        }

        // Update lead status and tag based on user response
        let updatedTag: string;
        if (userResponse.toLowerCase() === 'yes') {
            lead.status = 'qualified';  // User answered "yes" to pre-approval
            updatedTag = 'serious';
        } else if (userResponse.toLowerCase() === 'no') {
            lead.status = 'unqualified';  // User answered "no" to pre-approval
            updatedTag = 'notserious';
        } else {
            logger.warn(`Invalid response: ${userResponse} for phone number: ${phoneNumber}`);
            throw new CustomError('Invalid user response', 400);
        }

        // Update the lead's tag
        lead.tag = updatedTag;

        // Save the updated lead
        await lead.save();

        logger.info(`Lead updated successfully for phone number: ${phoneNumber} with status: ${lead.status}`);

        res.status(200).json({
            success: true,
            message: `Lead updated successfully with status: ${lead.status}`,
            lead,
        });
    } catch (error: any) {
        logger.error(`Error processing WhatsApp result: ${error.message}`);
        res.status(error.statusCode || 500).json({
            success: false,
            message: error.message || 'Internal Server Error',
        });
    }
};
