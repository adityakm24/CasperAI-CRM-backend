import { Request, Response, NextFunction } from 'express';
import { ObjectSchema } from 'joi';
import { sendErrorResponse, sendBadRequestResponse } from '../utils/responseHandler';

export function validationMiddleware(schema: ObjectSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
        const { error } = schema.validate(req.body, { abortEarly: false });

        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.context?.key,
                message: detail.message,
            }));

            sendErrorResponse(res, 'Validation failed', errors, 422);
        } else {
            next();
        }
    };
}


