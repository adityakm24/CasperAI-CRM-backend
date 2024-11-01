import Lead from '../models/Leads';
import Webhook from '../models/Webhook';
import { randomBytes } from 'crypto';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';
import fetch from 'node-fetch';

// Service to generate a webhook for a specific user
export const generateWebhookService = async (userId: string) => {
    const existingWebhook = await Webhook.findOne({ userId });
    if (existingWebhook) {
        logger.warn(`Webhook already exists for user: ${userId}`);
        throw new CustomError('Webhook already exists for this user', 409);
    }

    const verifyToken = randomBytes(20).toString('hex');

    const newWebhook = new Webhook({
        userId,
        verifyToken,
    });

    await newWebhook.save();

    logger.info(`Webhook created successfully for user: ${userId}`);
    return {
        url: `/webhook`,
        verifyToken,
    };
};

// Service to process incoming leads from the CRM webhook
export const processWebhookLeadService = async (phoneNumber: string, firstName: string, lastName: string, crmIdentifier: string | undefined, verifyToken: string) => {
    const userWebhook = await Webhook.findOne({ verifyToken });
    if (!userWebhook) {
        logger.warn('Invalid webhook request, token not found');
        throw new CustomError('Invalid verify token', 403);
    }

    if (!phoneNumber || !firstName || !lastName) {
        logger.warn('Missing required fields in webhook payload');
        throw new CustomError('Missing required fields: phoneNumber, firstName, or lastName', 400);
    }

    const updatedLead = await Lead.findOneAndUpdate(
        { phoneNumber, userId: userWebhook.userId },
        {
            phoneNumber,
            firstName,
            lastName,
            crmIdentifier: crmIdentifier || '',
            status: 'fresh',
            userId: userWebhook.userId,
            tag: 'CRM Lead',
        },
        { new: true, upsert: true }
    );

    logger.info(`Lead ${updatedLead ? 'updated' : 'created'} successfully for user: ${userWebhook.userId}`);

    // API call to trigger chat service
    const apiUrl = 'https://peaceful-bayou-47899-85cf30be7379.herokuapp.com/trigger-chat';
    const apiBody = {
        phoneNumber: phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`
    };

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(apiBody)
        });

        // Check if the external API call was successful
        if (!response.ok) {
            logger.error('Failed to trigger chat API after lead update/add', { status: response.status, statusText: response.statusText });
            throw new CustomError('Failed to trigger chat API', response.status);
        }

        logger.info('Chat API triggered successfully after lead update/add');
    } catch (error) {
        logger.error('Error in calling chat API', { error });
        throw new CustomError('Error in calling chat API', 500);
    }

    return updatedLead;
};
