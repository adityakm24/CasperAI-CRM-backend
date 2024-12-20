import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import logger from '../config/logger';
import { Types } from 'mongoose';
// Middleware to authorize lead creation (checks if req.user exists)

export const authorizeLeadCreation = (req: Request, res: Response, next: NextFunction) => {
  const user = req.user as { userId: string | Types.ObjectId }; 

  if (!user || !user.userId) {  // Check if req.user contains userId
    logger.warn('Unauthorized attempt to create lead');
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const userId = user.userId.toString(); // Convert userId to string if needed
  next();
};


// Middleware to validate lead input data
export const validateLeadInput = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Invalid lead input data', { errors: errors.array() });
    return res.status(422).json({ errors: errors.array() });
  }
  next();
};
