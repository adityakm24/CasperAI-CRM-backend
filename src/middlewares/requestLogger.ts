import { Request, Response, NextFunction } from 'express';
import logger from '../config/logger';

const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
    const startHrTime = process.hrtime();

    res.on('finish', () => {
        const elapsedHrTime = process.hrtime(startHrTime);
        const elapsedTimeInMs = elapsedHrTime[0] * 1000 + elapsedHrTime[1] / 1e6;
        const logLevel = elapsedTimeInMs > 1000 ? 'warn' : 'info';

        logger[logLevel](`${req.method} ${req.url} - ${elapsedTimeInMs}ms`, {
            method: req.method,
            url: req.url,
            status: res.statusCode,
            responseTime: elapsedTimeInMs,
            ip: req.ip,
        });
    });

    next();
};

export default requestLogger;
