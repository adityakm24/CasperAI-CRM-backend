import { Response } from 'express';

export const sendSuccessResponse = (
    res: Response,
    data: any,
    message: string = 'Success',
    statusCode: number = 200
) => {
    res.status(statusCode).json({
        success: true,
        message,
        data,
    });
};

export const sendCreatedResponse = (
    res: Response,
    data: any,
    message: string = 'Resource created successfully.'
) => {
    sendSuccessResponse(res, data, message, 201);
};

export const sendNoContentResponse = (
    res: Response,
    message: string = 'No content.'
) => {
    res.status(204).json({
        success: true,
        message,
    });
};

export const sendBadRequestResponse = (
    res: Response,
    message: string = 'Bad request. Please check your input.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 400);
};

export const sendUnauthorizedResponse = (
    res: Response,
    message: string = 'Unauthorized access. Please log in.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 401);
};

export const sendForbiddenResponse = (
    res: Response,
    message: string = 'Access forbidden. You do not have permission to access this resource.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 403);
};

export const sendNotFoundResponse = (
    res: Response,
    message: string = 'Resource not found.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 404);
};

export const sendConflictResponse = (
    res: Response,
    message: string = 'Conflict occurred. The request could not be processed.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 409);
};

export const sendUnprocessableEntityResponse = (
    res: Response,
    message: string = 'Unprocessable entity. The server understands the request but can\'t process it.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 422);
};

export const sendInternalServerErrorResponse = (
    res: Response,
    message: string = 'Internal server error. Please try again later.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 500);
};

export const sendBadGatewayResponse = (
    res: Response,
    message: string = 'Bad gateway. The server received an invalid response from the upstream server.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 502);
};

export const sendServiceUnavailableResponse = (
    res: Response,
    message: string = 'Service unavailable. Please try again later.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 503);
};

export const sendGatewayTimeoutResponse = (
    res: Response,
    message: string = 'Gateway timeout. The server did not receive a timely response from the upstream server.',
    errors: any[] = []
) => {
    sendErrorResponse(res, message, errors, 504);
};

export const sendErrorResponse = (
    res: Response,
    message: string = 'Error occurred',
    errors: any[] = [],
    statusCode: number = 500
) => {
    res.status(statusCode).json({
        success: false,
        message,
        errors,
    });
};


export const sendTooManyRequestsResponse = (
    res: Response,
    message: string = 'Too many requests',
    errors: any[] = [],
    statusCode: number = 429
) => {
    res.status(statusCode).json({
        success: false,
        message,
        errors,
    });
};
