import { Request, Response, NextFunction } from 'express';
import * as leadService from '../services/leadService';
import { sendCreatedResponse, sendInternalServerErrorResponse } from '../utils/responseHandler';
import logger from '../config/logger';

// Interface for user with _id and userId
interface AuthenticatedUser {
    _id: string;
    userId: any;
}

export const addLead = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = req.user as AuthenticatedUser | undefined;
        if (!user || !user.userId) {  // Check for userId instead of _id
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const leadData = {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            phoneNumber: req.body.phoneNumber,
            crmIdentifier: req.body.crmIdentifier || '',
            status: req.body.status || 'fresh',
            notes: req.body.notes || '',
            userId: user.userId,  // Use user.userId
            propertyInterest: req.body.propertyInterest,
            tag: req.body.tag || null,
        };

        const result = await leadService.createLead(leadData);
        return sendCreatedResponse(res, result, 'Lead created successfully.');
    } catch (error) {
        logger.error('Error creating new lead', { error });
        return sendInternalServerErrorResponse(res, 'Failed to create the lead.');
    }
};

