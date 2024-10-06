import { Request, Response, NextFunction } from 'express';
import * as authService from '../services/authService';
import { validationResult } from 'express-validator';
import logger from '../config/logger';
import {
    sendSuccessResponse,
    sendCreatedResponse,
    sendUnprocessableEntityResponse,
    sendInternalServerErrorResponse,
    sendUnauthorizedResponse,
    sendConflictResponse
} from '../utils/responseHandler';
import { CustomError } from '../middlewares/errorHandler';
import { verifyRecaptcha } from '../utils/recaptcha';
import { config } from '../config/env';
import { getGoogleProfile, oAuth2Client } from '../config/googleOAuth';
import { handleGoogleAuth, handleGoogleSignIn } from '../services/authService';
import { createRefreshToken, createToken } from '../utils/tokenUtils';
import Security from '../models/Security';
import { addDays } from 'date-fns';
import { validateToken } from '../utils/tokenUtils';


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

        if (config.nodeEnv  === 'development') {
            console.log('Skipping reCAPTCHA verification for development.');
        } else {
            const { recaptchaToken } = req.body;
            if (recaptchaToken) {
                await verifyRecaptcha(recaptchaToken);
            }
        }

        const result = await authService.registerAgent(agentData , res);
        return sendCreatedResponse(res, result, 'User registered successfully.');
    } catch (error) {
        logger.error('Unexpected error during registration', {
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
        });
        if (error instanceof CustomError && error.statusCode === 409) {
            return sendConflictResponse(res, error.message);
        } else {
            next(error);
        }
    }
};


export const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (config.nodeEnv === 'development') {
            console.log('Skipping reCAPTCHA verification for development.');
        } else {
            const { recaptchaToken } = req.body;
            if (recaptchaToken) {
                await verifyRecaptcha(recaptchaToken);
            }
        }

        const { email, password } = req.body;
        const result = await authService.loginUser(email, password, res);
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

export const verifyOtp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, otp } = req.body;

        logger.info('Starting OTP verification process', { email, otp });

        const result = await authService.verifyOtp(email, otp); 
        return sendSuccessResponse(res, result, 'OTP verified successfully.');
    } catch (error) {
        if (error instanceof CustomError) {
            logger.error('Custom error during OTP verification', { error: error.message });
            return next(error);
        } else if (error instanceof Error) {
            logger.error('Unexpected error during OTP verification', { error: error.message });
            return sendInternalServerErrorResponse(res, 'An unexpected error occurred.');
        } else {
            logger.error('Unknown error type during OTP verification');
            return sendInternalServerErrorResponse(res, 'An unknown error occurred.');
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
        const { refreshToken } = req.cookies; 

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


export const initiateGoogleAuth = (req: Request, res: Response) => {
    const authorizeUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
        prompt: 'consent'
    });
    res.redirect(authorizeUrl);
};

export const googleCallback = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { code } = req.query;
        const profile = await getGoogleProfile(code as string);

        logger.info('Handling Google OAuth', { profile });
        const user = await handleGoogleSignIn(profile) || await handleGoogleAuth(profile);

        if (!user) {
            return sendInternalServerErrorResponse(res, 'User authentication failed.');
        }

        const accessToken = await createToken({ userId: user._id, email: user.email });
        const refreshToken = await createRefreshToken({ userId: user._id, email: user.email });

        const securityRecord = await Security.findById(user.security);
        if (securityRecord) {
            securityRecord.refreshToken = refreshToken;
            securityRecord.refreshTokenExpires = addDays(new Date(), 7);
            await securityRecord.save();
        }

        res.cookie('accessToken', accessToken, {
            httpOnly: true, 
            secure: config.nodeEnv === 'production', 
            sameSite: 'strict', 
            maxAge: 5 * 60 * 60 * 1000, // 5 hours
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: config.nodeEnv === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        return res.redirect(`${config.frontendUrl}/dashboard`);
    } catch (error) {
        logger.error('Google OAuth callback error', { error: (error as Error).message });
        return sendInternalServerErrorResponse(res, 'An unexpected error occurred during authentication.');
    }
};

export const verifyToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const token = req.cookies.accessToken || req.headers.authorization;

        if (!token) {
            logger.warn('Authorization failed: No token provided in cookies');
            return sendUnauthorizedResponse(res, 'Authorization failed: No token provided');
        }

        const payload = await validateToken(token);

        if (!payload) {
            throw new CustomError('Invalid or expired token', 401);
        }

        logger.info('Token verification successful', { userId: payload.userId });

        return sendSuccessResponse(res, { userId: payload.userId, email: payload.email }, 'Token is valid.');
    } catch (error) {
        logger.error('Token verification failed', { error: (error as Error).message });
        return sendUnauthorizedResponse(res, 'Invalid or expired token');
    }
};
