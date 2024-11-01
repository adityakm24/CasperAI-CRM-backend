import * as authController from '../../controllers/authController';
import * as authService from '../../services/authService';
import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import { sendSuccessResponse, sendCreatedResponse, sendUnauthorizedResponse, sendInternalServerErrorResponse, sendConflictResponse } from '../../utils/responseHandler';
import { CustomError } from '../../middlewares/errorHandler';
import { sendUnprocessableEntityResponse } from '../../utils/responseHandler';
import { createRefreshToken, createToken, validateToken } from '../../utils/tokenUtils';
import Security from '../../models/Security';
import { oAuth2Client } from '../../config/googleOAuth';


jest.mock('../../services/authService');
jest.mock('express-validator');
jest.mock('../../utils/responseHandler');
jest.mock('../../utils/recaptcha');

describe('AuthController', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let nextFunction: NextFunction;

    beforeEach(() => {
        mockReq = {
            body: {},
            cookies: {}
        };

        mockRes = {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
            cookie: jest.fn(),
            redirect: jest.fn(),
        };

        nextFunction = jest.fn();
        jest.clearAllMocks();
    });

    describe('register', () => {
        it('should call registerAgent and return a created response', async () => {
            mockReq.body = {
                email: 'test@example.com',
                password: 'password123',
                firstName: 'John',
                lastName: 'Doe',
            };

            (authService.registerAgent as jest.Mock).mockResolvedValue({ userId: '123' });

            await authController.register(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.registerAgent).toHaveBeenCalledWith(expect.any(Object), expect.any(Object));
            expect(sendCreatedResponse).toHaveBeenCalledWith(mockRes, { userId: '123' }, 'User registered successfully.');
        });

        it('should handle validation errors for invalid fields', async () => {
            mockReq.body = { email: 'invalid email' };
            (validationResult as unknown as jest.Mock).mockReturnValue({ isEmpty: jest.fn().mockReturnValue(false), array: jest.fn().mockReturnValue([{ msg: 'Invalid email' }]) });
        
            await authController.register(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(sendUnprocessableEntityResponse).toHaveBeenCalledWith(mockRes, 'Invalid input data.', [{ msg: 'Invalid email' }]);
        });
        

        it('should call next with an unexpected error', async () => {
            const error = new Error('Unexpected error');
            (authService.registerAgent as jest.Mock).mockRejectedValue(error);

            await authController.register(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });

        it('should handle missing required fields', async () => {
            mockReq.body = {};
            (validationResult as unknown as jest.Mock).mockReturnValue({
                isEmpty: jest.fn().mockReturnValue(false),
                array: jest.fn().mockReturnValue([{ msg: 'Required fields missing' }]),
            });
        
            await authController.register(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(sendUnprocessableEntityResponse).toHaveBeenCalledWith(mockRes, 'Invalid input data.', [{ msg: 'Required fields missing' }]);
        });
        

        it('should handle conflict error if email already exists', async () => {
            const error = new CustomError('Email already exists', 409);
            (authService.registerAgent as jest.Mock).mockRejectedValue(error);
        
            await authController.register(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(nextFunction).toHaveBeenCalledWith(error);
        });
        
    });

    describe('login', () => {
        it('should call loginUser and return success response', async () => {
            mockReq.body = { email: 'test@example.com', password: 'password123' };
            (authService.loginUser as jest.Mock).mockResolvedValue({ userId: '123' });

            await authController.login(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.loginUser).toHaveBeenCalledWith('test@example.com', 'password123', expect.any(Object));
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { userId: '123' }, 'User logged in successfully.');
        });

        it('should handle unexpected errors during login', async () => {
            const error = new Error('Unexpected error');
            (authService.loginUser as jest.Mock).mockRejectedValue(error);

            await authController.login(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });

        it('should handle missing email or password validation error', async () => {
            mockReq.body = { email: '' };
            (validationResult as unknown as jest.Mock).mockReturnValue({ isEmpty: jest.fn().mockReturnValue(false), array: jest.fn().mockReturnValue([{ msg: 'Email is required' }]) });
        
            await authController.login(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(sendUnprocessableEntityResponse).toHaveBeenCalledWith(mockRes, 'Invalid input data.', [{ msg: 'Email is required' }]);
        });

        it('should handle incorrect password', async () => {
            const error = new CustomError('Incorrect password', 401);
            (authService.loginUser as jest.Mock).mockRejectedValue(error);
        
            await authController.login(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(nextFunction).toHaveBeenCalledWith(error);
        });

        it('should handle missing token on successful login', async () => {
            (authService.loginUser as jest.Mock).mockResolvedValue({});
            
            await authController.login(mockReq as Request, mockRes as Response, nextFunction);
            
            expect(sendUnauthorizedResponse).toHaveBeenCalledWith(mockRes, 'Token generation failed');
        });        
        
    });

    describe('verifyOtp', () => {
        it('should call verifyOtp and return success response', async () => {
            mockReq.body = { email: 'test@example.com', otp: '123456' };
            (authService.verifyOtp as jest.Mock).mockResolvedValue({ message: 'OTP verified successfully' });

            await authController.verifyOtp(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.verifyOtp).toHaveBeenCalledWith('test@example.com', '123456');
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { message: 'OTP verified successfully' }, 'OTP verified successfully.');
        });

        it('should handle CustomError during OTP verification', async () => {
            const error = new CustomError('Invalid OTP', 400);
            (authService.verifyOtp as jest.Mock).mockRejectedValue(error);

            await authController.verifyOtp(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });
    });

    describe('resendOtp', () => {
        it('should call resendOtp and return success response', async () => {
            mockReq.body = { email: 'test@example.com' };
            (authService.resendOtp as jest.Mock).mockResolvedValue({ message: 'OTP resent successfully' });

            await authController.resendOtp(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.resendOtp).toHaveBeenCalledWith('test@example.com', expect.any(Object));
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { message: 'OTP resent successfully' }, 'OTP resent successfully.');
        });

        it('should handle errors during OTP resend', async () => {
            const error = new CustomError('User not found', 404);
            (authService.resendOtp as jest.Mock).mockRejectedValue(error);

            await authController.resendOtp(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });

        it('should handle missing email in request body', async () => {
            mockReq.body = {};
            (validationResult as unknown as jest.Mock).mockReturnValue({
                isEmpty: jest.fn().mockReturnValue(false),
                array: jest.fn().mockReturnValue([{ msg: 'Email is required' }]),
            });
        
            await authController.resendOtp(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(sendUnprocessableEntityResponse).toHaveBeenCalledWith(mockRes, 'Invalid input data.', [{ msg: 'Email is required' }]);
        });

        it('should handle rate limit for resend OTP', async () => {
            const error = new CustomError('Too many OTP requests', 429);
            (authService.resendOtp as jest.Mock).mockRejectedValue(error);
        
            await authController.resendOtp(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(nextFunction).toHaveBeenCalledWith(error);
        });        
        
    });

    describe('requestPasswordReset', () => {
        it('should request password reset and send success response', async () => {
            mockReq.body = { email: 'test@example.com' };
            (authService.requestPasswordReset as jest.Mock).mockResolvedValue({ message: 'Password reset email sent' });

            await authController.requestPasswordReset(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.requestPasswordReset).toHaveBeenCalledWith('test@example.com');
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { message: 'Password reset email sent' }, 'Password reset email sent.');
        });

        it('should handle errors during password reset request', async () => {
            const error = new Error('Unexpected error');
            (authService.requestPasswordReset as jest.Mock).mockRejectedValue(error);

            await authController.requestPasswordReset(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });
    });

    describe('resetPassword', () => {
        it('should reset password and return success response', async () => {
            mockReq.body = { token: 'resetToken', newPassword: 'newPassword123' };
            (validationResult as unknown as jest.Mock).mockReturnValue({ isEmpty: jest.fn().mockReturnValue(true) });
            (authService.resetPassword as jest.Mock).mockResolvedValue({ message: 'Password has been reset' });

            await authController.resetPassword(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.resetPassword).toHaveBeenCalledWith('resetToken', 'newPassword123');
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { message: 'Password has been reset' }, 'Password has been reset successfully.');
        });

        it('should handle validation errors', async () => {
            (validationResult as unknown as jest.Mock).mockReturnValue({
                isEmpty: jest.fn().mockReturnValue(false),
                array: jest.fn().mockReturnValue([{ msg: 'Invalid input' }]),
            });

            await authController.resetPassword(mockReq as Request, mockRes as Response, nextFunction);

            expect(sendUnprocessableEntityResponse).toHaveBeenCalledWith(mockRes, 'Invalid input data.', [{ msg: 'Invalid input' }]);
        });

        it('should handle unexpected errors during password reset', async () => {
            const error = new Error('Unexpected error');
            (authService.resetPassword as jest.Mock).mockRejectedValue(error);

            await authController.resetPassword(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });

        it('should handle validation error for missing token', async () => {
            mockReq.body = {};
        
            await authController.resetPassword(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(sendUnprocessableEntityResponse).toHaveBeenCalledWith(mockRes, 'Token and new password are required.');
        });

        it('should handle expired reset token', async () => {
            const error = new CustomError('Token expired', 400);
            (authService.resetPassword as jest.Mock).mockRejectedValue(error);
        
            await authController.resetPassword(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(nextFunction).toHaveBeenCalledWith(error);
        });
        
        
    });

    describe('refreshAccessToken', () => {
        it('should refresh access token and return success response', async () => {
            mockReq.cookies = { refreshToken: 'validRefreshToken' };
            (authService.refreshToken as jest.Mock).mockResolvedValue({ accessToken: 'newAccessToken' });

            await authController.refreshAccessToken(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.refreshToken).toHaveBeenCalledWith('validRefreshToken');
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { accessToken: 'newAccessToken' }, 'New access token issued.');
        });

        it('should handle missing refresh token', async () => {
            mockReq.cookies = {};

            await authController.refreshAccessToken(mockReq as Request, mockRes as Response, nextFunction);

            expect(sendUnauthorizedResponse).toHaveBeenCalledWith(mockRes, 'Refresh token is required.');
        });

        it('should handle unexpected errors during token refresh', async () => {
            const error = new Error('Unexpected error');
            (authService.refreshToken as jest.Mock).mockRejectedValue(error);

            await authController.refreshAccessToken(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });

        it('should handle invalid refresh token', async () => {
            const error = new CustomError('Invalid refresh token', 401);
            mockReq.cookies = { refreshToken: 'invalidRefreshToken' };
            (authService.refreshToken as jest.Mock).mockRejectedValue(error);
        
            await authController.refreshAccessToken(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(nextFunction).toHaveBeenCalledWith(error);
        });
        
    });

    describe('logout', () => {
        it('should log out user and return success response', async () => {
            mockReq.body = { userId: '123' };
            (authService.logoutUser as jest.Mock).mockResolvedValue({ message: 'User logged out successfully' });

            await authController.logout(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.logoutUser).toHaveBeenCalledWith('123', expect.any(Object));
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { message: 'User logged out successfully' }, 'User logged out successfully.');
        });

        it('should handle missing user ID', async () => {
            mockReq.body = {};

            await authController.logout(mockReq as Request, mockRes as Response, nextFunction);

            expect(sendUnauthorizedResponse).toHaveBeenCalledWith(mockRes, 'User ID is required for logout');
        });

        it('should handle unexpected errors during logout', async () => {
            const error = new Error('Unexpected error');
            (authService.logoutUser as jest.Mock).mockRejectedValue(error);

            await authController.logout(mockReq as Request, mockRes as Response, nextFunction);

            expect(nextFunction).toHaveBeenCalledWith(error);
        });
    });

    describe('initiateGoogleAuth', () => {
        it('should redirect to Google OAuth URL', () => {
            const mockAuthorizeUrl = 'https://google.com/oauth2/auth';
            (oAuth2Client.generateAuthUrl as jest.Mock).mockReturnValue(mockAuthorizeUrl);

            authController.initiateGoogleAuth(mockReq as Request, mockRes as Response);

            expect(oAuth2Client.generateAuthUrl).toHaveBeenCalledWith({
                access_type: 'offline',
                scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
                prompt: 'consent'
            });
            expect(mockRes.redirect).toHaveBeenCalledWith(mockAuthorizeUrl);
        });
    });

    describe('googleCallback', () => {
        it('should handle Google OAuth callback and redirect to dashboard', async () => {
            const mockProfile = { email: 'test@example.com' };
            const mockUser = { _id: 'userId', email: 'test@example.com', security: 'securityId' };
            const mockCode = 'authCode';

            mockReq.query = { code: mockCode };
            (authService.handleGoogleSignIn as jest.Mock).mockResolvedValue(null);
            (authService.handleGoogleAuth as jest.Mock).mockResolvedValue(mockUser);
            (createToken as jest.Mock).mockResolvedValue('accessToken');
            (createRefreshToken as jest.Mock).mockResolvedValue('refreshToken');
            (Security.findById as jest.Mock).mockResolvedValue({
                refreshToken: 'oldRefreshToken',
                refreshTokenExpires: new Date(),
                save: jest.fn()
            });

            await authController.googleCallback(mockReq as Request, mockRes as Response, nextFunction);

            expect(authService.handleGoogleAuth).toHaveBeenCalledWith(mockProfile);
            expect(createToken).toHaveBeenCalledWith({ userId: mockUser._id, email: mockUser.email });
            expect(createRefreshToken).toHaveBeenCalledWith({ userId: mockUser._id, email: mockUser.email });
            expect(mockRes.cookie).toHaveBeenCalledWith('accessToken', 'accessToken', expect.any(Object));
            expect(mockRes.cookie).toHaveBeenCalledWith('refreshToken', 'refreshToken', expect.any(Object));
            expect(mockRes.redirect).toHaveBeenCalledWith(`${process.env.FRONTEND_URL}/dashboard`);
        });

        it('should handle errors during Google OAuth callback', async () => {
            const error = new Error('OAuth Error');
            (authService.handleGoogleAuth as jest.Mock).mockRejectedValue(error);

            await authController.googleCallback(mockReq as Request, mockRes as Response, nextFunction);

            expect(sendInternalServerErrorResponse).toHaveBeenCalledWith(mockRes, 'An unexpected error occurred during authentication.');
        });

        it('should handle missing authorization code in query', async () => {
            mockReq.query = {};
            await authController.googleCallback(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(sendInternalServerErrorResponse).toHaveBeenCalledWith(mockRes, 'Authorization code is missing.');
        });
        
        it('should handle invalid Google profile data', async () => {
            mockReq.query = { code: 'authCode' };
            (authService.handleGoogleAuth as jest.Mock).mockRejectedValue(new CustomError('Invalid Google profile data', 400));
        
            await authController.googleCallback(mockReq as Request, mockRes as Response, nextFunction);
        
            expect(nextFunction).toHaveBeenCalledWith(new CustomError('Invalid Google profile data', 400));
        });
        
    });

    describe('verifyToken', () => {
        it('should verify token and return success response', async () => {
            const mockToken = 'validAccessToken';
            const mockPayload = { userId: '123', email: 'test@example.com' };

            mockReq.cookies = { accessToken: mockToken };
            (validateToken as jest.Mock).mockResolvedValue(mockPayload);

            await authController.verifyToken(mockReq as Request, mockRes as Response, nextFunction);

            expect(validateToken).toHaveBeenCalledWith(mockToken);
            expect(sendSuccessResponse).toHaveBeenCalledWith(mockRes, { userId: '123', email: 'test@example.com' }, 'Token is valid.');
        });

        it('should handle missing token in request', async () => {
            mockReq.cookies = {};

            await authController.verifyToken(mockReq as Request, mockRes as Response, nextFunction);

            expect(sendUnauthorizedResponse).toHaveBeenCalledWith(mockRes, 'Authorization failed: No token provided');
        });

        it('should handle invalid or expired token', async () => {
            const error = new CustomError('Invalid or expired token', 401);
            (validateToken as jest.Mock).mockRejectedValue(error);

            await authController.verifyToken(mockReq as Request, mockRes as Response, nextFunction);

            expect(sendUnauthorizedResponse).toHaveBeenCalledWith(mockRes, 'Invalid or expired token');
        });
    });

});
