import rateLimit from 'express-rate-limit';
import { sendTooManyRequestsResponse } from '../utils/responseHandler'; 
import logger from '../config/logger';


export const rateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 Mins For now
    max: 100, 
    standardHeaders: true, 
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        return sendTooManyRequestsResponse(res, 'Too many requests, please try again later.');
    },
    keyGenerator: (req) => req.ip || '',
});
