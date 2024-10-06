import { Request, Response, NextFunction } from 'express';
import { validateToken, validateRefreshToken } from '../utils/tokenUtils';
import logger from '../config/logger';
import { sendUnauthorizedResponse } from '../utils/responseHandler';
import { CustomError } from '../middlewares/errorHandler';

export const authorize = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            logger.warn('Authorization failed: No token provided');
            return sendUnauthorizedResponse(res, 'Authorization failed: No token provided');
        }

        const token = authHeader.split(' ')[1];
        const payload: any = await validateToken(token);

        if (!payload) {
            throw new CustomError('Invalid or expired token', 401);
        }

        req.user = payload;

        if (!(req.user as any).userId) {
            throw new CustomError('Invalid user data in token', 401);
        }

        logger.info('Authorization successful', {  userId: (req.user as any).userId });
        next();
    } catch (error) {
        logger.error('Authorization failed', { error: (error as Error).message });
        return sendUnauthorizedResponse(res, (error as Error).message || 'Authorization failed: Invalid or expired token');
    }
};

export const authorizeRefreshToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const  refreshToken  = req.cookies.refreshToken;

        if (!refreshToken) {
            logger.warn('Authorization failed: No refresh token provided');
            return sendUnauthorizedResponse(res, 'Authorization failed: No refresh token provided');
        }

        const payload: any = await validateRefreshToken(refreshToken);

        if (!payload) {
            throw new CustomError('Invalid or expired refresh token', 401);
        }

        req.user = payload;

        if (!(req.user as any).userId) {
            throw new CustomError('Invalid user data in token', 401);
        }

        logger.info('Refresh token authorization successful', {  userId: (req.user as any).userId });
        next();
    } catch (error) {
        logger.error('Refresh token authorization failed', { error: (error as Error).message });
        return sendUnauthorizedResponse(res, (error as Error).message || 'Authorization failed: Invalid or expired refresh token');
    }
};
