import { Request, Response, NextFunction } from 'express';
import * as authService from '../services/authService';
import { validationResult } from 'express-validator';
import logger from '../config/logger';
import {
    sendSuccessResponse,
    sendCreatedResponse,
    sendUnprocessableEntityResponse,
    sendInternalServerErrorResponse,
    sendUnauthorizedResponse
} from '../utils/responseHandler';
import { CustomError } from '../middlewares/errorHandler';
import { verifyRecaptcha } from '../utils/recaptcha';
import passport from 'passport';


export const register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const agentData = {
            email: req.body.email,
            password: req.body.password,
            personalInfo: {
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                phoneNumber1: req.body.phoneNumber1,
                countryCode: req.body.countryCode,
            },
            ...req.body
        };

        if (process.env.NODE_ENV === 'development') {
            console.log('Skipping reCAPTCHA verification for development.');
        } else {
            const { recaptchaToken } = req.body;
            if (recaptchaToken) {
                await verifyRecaptcha(recaptchaToken);
            }
        }

        const result = await authService.registerAgent(agentData);
        return sendCreatedResponse(res, result, 'User registered successfully.');
    } catch (error) {
        logger.error('Unexpected error during registration', {
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
        });
        if (!(error instanceof CustomError)) {
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred.');
        } else {
            next(error);
        }
    }
};


export const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (process.env.NODE_ENV === 'development') {
            console.log('Skipping reCAPTCHA verification for development.');
        } else {
            const { recaptchaToken } = req.body;
            if (recaptchaToken) {
                await verifyRecaptcha(recaptchaToken);
            }
        }

        const { email, password } = req.body;
        const result = await authService.loginUser(email, password);
        return sendSuccessResponse(res, result, 'User logged in successfully.');
    } catch (error) {
        if (!(error instanceof CustomError)) {
            logger.error('Unexpected error during login', { error });
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred.');
        } else {
            next(error);
        }
    }
};

export const verifyEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { token } = req.query as { token: string };

        const result = await authService.verifyEmail(token);
        return sendSuccessResponse(res, result, 'Email verified successfully.');
    } catch (error) {
        if (!(error instanceof CustomError)) {
            logger.error('Unexpected error during email verification', { error });
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred.');
        } else {
            next(error);
        }
    }
};

export const requestPasswordReset = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email } = req.body;
        const result = await authService.requestPasswordReset(email);
        return sendSuccessResponse(res, result, 'Password reset email sent.');
    } catch (error) {
        if (!(error instanceof CustomError)) {
            logger.error('Unexpected error during password reset request', { error });
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred.');
        } else {
            next(error);
        }
    }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Validation failed during password reset', { errors: errors.array() });
            return sendUnprocessableEntityResponse(res, 'Invalid input data.', errors.array());
        }

        const { token, newPassword } = req.body;
        const result = await authService.resetPassword(token, newPassword);
        return sendSuccessResponse(res, result, 'Password has been reset successfully.');
    } catch (error) {
        if (!(error instanceof CustomError)) {
            logger.error('Unexpected error during password reset', { error });
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred.');
        } else {
            next(error);
        }
    }
};

export const refreshAccessToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            logger.warn('Refresh token is missing and email is missing');
            return sendUnauthorizedResponse(res, 'Refresh token is required.');
        }

        const accessToken = await authService.refreshToken(refreshToken);

        return sendSuccessResponse(res, { accessToken }, 'New access token issued.');
    } catch (error) {
        if (!(error instanceof CustomError)) {
            logger.error('Unexpected error during token refresh', { error });
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred.');
        } else {
            next(error);
        }
    }
};


export const googleCallback = (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate('google', (err: Error | null, user: any, info: any) => {
        if (err) {
            logger.error('Google OAuth callback error', { error: err.message });
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred during authentication.');
        }
        if (!user) {
            return sendInternalServerErrorResponse(res, 'User authentication failed.');
        }

        const { accessToken, refreshToken } = info;

        return sendSuccessResponse(res, {
            message: 'Authentication successful',
            accessToken,
            refreshToken,
        }, 'Logged in successfully.');
    })(req, res, next);
};




