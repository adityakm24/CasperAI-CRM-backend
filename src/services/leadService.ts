// leadService.ts
import Lead from '../models/Leads';
import logger from '../config/logger';
import { CustomError } from '../middlewares/errorHandler';

export const createLead = async (leadData: any) => {
    try {
        const newLead = new Lead(leadData);
        const savedLead = await newLead.save();
        logger.info('New lead created successfully', { leadId: savedLead._id });
        return savedLead;
    } catch (error) {
        logger.error('Error creating new lead', { error });
        throw new CustomError('Failed to create lead', 500);
    }
};
