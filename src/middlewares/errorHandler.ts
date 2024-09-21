import { Request, Response, NextFunction } from 'express';
import logger from '../config/logger';


export class CustomError extends Error {
    public statusCode: number;

    constructor(message: string, statusCode: number) {
        super(message);
        this.statusCode = statusCode;
        Error.captureStackTrace(this, this.constructor);
    }
}

export function errorHandler(err: any, req: Request, res: Response, next: NextFunction) {
    if (!err.statusCode || err.statusCode === 500) {
        logger.error(`Internal Server Error: ${err.message}`, { stack: err.stack });
    } else {
        logger.warn(`Error: ${err.message}`, { statusCode: err.statusCode });
    }

    res.status(err.statusCode || 500).json({
        success: false,
        message: err.message || 'Internal Server Error',
        errors: err.errors || []
    });
}
