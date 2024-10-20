import Lead from '../models/Leads';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';

// Service to process WhatsApp bot result
export const processWhatsAppResultService = async (phoneNumber: string, userResponse: string) => {
    if (!phoneNumber || !userResponse) {
        logger.warn('Missing required fields in WhatsApp bot payload');
        throw new CustomError('Missing required fields: phoneNumber or userResponse', 400);
    }

    const lead = await Lead.findOne({ phoneNumber });
    if (!lead) {
        logger.warn(`No lead found with phone number: ${phoneNumber}`);
        throw new CustomError('No lead found with this phone number', 404);
    }

    let updatedTag: string;
    if (userResponse.toLowerCase() === 'yes') {
        lead.status = 'qualified';
        updatedTag = 'serious';
    } else if (userResponse.toLowerCase() === 'no') {
        lead.status = 'unqualified';
        updatedTag = 'notserious';
    } else {
        logger.warn(`Invalid response: ${userResponse} for phone number: ${phoneNumber}`);
        throw new CustomError('Invalid user response', 400);
    }

    lead.tag = updatedTag;
    await lead.save();

    logger.info(`Lead updated successfully for phone number: ${phoneNumber} with status: ${lead.status}`);
    return lead;
};
