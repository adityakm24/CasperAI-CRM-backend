import { Request, Response, NextFunction } from 'express';
import logger from '../config/logger';
import { sendErrorResponse } from '../utils/responseHandler';

export class CustomError extends Error {
    public statusCode: number;

    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode;
        Error.captureStackTrace(this, this.constructor);
    }
}

export function errorHandler(err: any, req: Request, res: Response, next: NextFunction) {
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Internal Server Error';
    const errors = err.errors || [];

    if (statusCode === 500) {
        logger.error(`Internal Server Error: ${message}`, { stack: err.stack });
    } else {
        logger.warn(`Error: ${message}`, { statusCode });
    }
    res.setHeader('Content-Type', 'application/json');
    sendErrorResponse(res, message, errors, statusCode);
}