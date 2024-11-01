import Lead from '../models/Leads';
import logger from '../config/logger';
import { CustomError } from '../middlewares/errorHandler';
import fetch from 'node-fetch';

export const createLead = async (leadData: any) => {
    try {
        // Create and save the new lead
        const newLead = new Lead(leadData);
        const savedLead = await newLead.save();
        logger.info('New lead created successfully', { leadId: savedLead._id });

        // Prepare data for the API call with a '+' prefix for the phone number
        const apiUrl = 'https://peaceful-bayou-47899-85cf30be7379.herokuapp.com/trigger-chat';
        const apiBody = {
            phoneNumber: leadData.phoneNumber.startsWith('+') ? leadData.phoneNumber : `+${leadData.phoneNumber}`
        };

        // Make a POST request to the external API
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(apiBody)
        });

        // Check if the external API call was successful
        if (!response.ok) {
            logger.error('Failed to trigger chat API', { status: response.status, statusText: response.statusText });
            throw new CustomError('Failed to trigger chat API', response.status);
        }

        logger.info('Chat API triggered successfully');
        return savedLead;
    } catch (error) {
        logger.error('Error in createLead function', { error });
        throw new CustomError('Failed to create lead and trigger chat', 500);
    }
};
