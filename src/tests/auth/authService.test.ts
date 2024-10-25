import * as authService from '../../services/authService';
import { CustomError } from '../../middlewares/errorHandler';
import bcrypt from 'bcryptjs';
import User from '../../models/Users';
import PersonalInfo from '../../models/PersonalInfo';
import Security from '../../models/Security';
import Subscription from '../../models/Subcriptions';
import { createToken, createRefreshToken, validateRefreshToken } from '../../utils/tokenUtils';
import { sendOtpEmail, sendPasswordResetEmail } from '../../utils/email';
import { startSession } from 'mongoose';
import { addDays, addMinutes } from 'date-fns';
import { readFileSync } from 'fs';

const mockSession = {
    startTransaction: jest.fn(),
    commitTransaction: jest.fn(),
    abortTransaction: jest.fn(),
    endSession: jest.fn(),
};
jest.mock('mongoose', () => ({
    startSession: jest.fn().mockReturnValue(mockSession),
}));

jest.mock('fs', () => ({
    readFileSync: jest.fn().mockReturnValue('privateKey or publicKey as needed'),
}));
jest.mock('bcryptjs', () => ({
    hash: jest.fn(),
    compare: jest.fn(),
}));
jest.mock('../../models/Users');
jest.mock('../../models/PersonalInfo');
jest.mock('../../models/Security');
jest.mock('../../models/Subcriptions');
jest.mock('../../utils/tokenUtils', () => ({
    createToken: jest.fn().mockResolvedValue('accessToken'),
    createRefreshToken: jest.fn().mockResolvedValue('refreshToken'),
    validateRefreshToken: jest.fn().mockResolvedValue({ userId: 'userId', email: 'test@example.com' }),
}));
jest.mock('../../utils/email');


describe('AuthService', () => {
    let signSpy: jest.SpyInstance;
    let verifySpy: jest.SpyInstance;

    beforeAll(() => {
        signSpy = jest.spyOn(require('paseto').V4, 'sign').mockResolvedValue('resetToken');
        verifySpy = jest.spyOn(require('paseto').V4, 'verify').mockResolvedValue({ email: 'test@example.com' });
    });

    afterEach(() => {
        jest.clearAllMocks();
        jest.restoreAllMocks();
    });

    describe('registerAgent', () => {
        let mockSession: any;

        beforeEach(() => {
            mockSession = startSession();
        });

        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should register a new agent and send OTP email', async () => {
            const agentData = {
                email: 'test@example.com',
                password: 'password123',
                personalInfo: {
                    firstName: 'John',
                    lastName: 'Doe',
                    phoneNumber1: '1234567890',
                    countryCode: 'US',
                },
            };

            (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);
            (Security.prototype.save as jest.Mock).mockResolvedValue({});
            (User.prototype.save as jest.Mock).mockResolvedValue({});
            (Subscription.create as jest.Mock).mockResolvedValue([{ _id: 'subscriptionId' }]);
            (PersonalInfo.prototype.save as jest.Mock).mockResolvedValue({});
            (createToken as jest.Mock).mockResolvedValue('accessToken');
            (createRefreshToken as jest.Mock).mockResolvedValue('refreshToken');

            const mockRes = {
                cookie: jest.fn()
            };

            const result = await authService.registerAgent(agentData, mockRes as any);

            expect(result).toHaveProperty('agent');
            expect(result.personalInfo.email).toBe('test@example.com');
            expect(sendOtpEmail).toHaveBeenCalledWith('test@example.com', expect.any(String));
        });

        it('should throw a 409 error if email already exists', async () => {
            const agentData = { email: 'existing@example.com', password: 'password123' };
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(true);

            await expect(authService.registerAgent(agentData, {} as any)).rejects.toThrow(CustomError);
            await expect(authService.registerAgent(agentData, {} as any)).rejects.toHaveProperty('statusCode', 409);
        });

        it('should handle errors during registration and abort transaction', async () => {
            const agentData = { email: 'error@example.com', password: 'password123' };
            (PersonalInfo.findOne as jest.Mock).mockRejectedValue(new Error('Database error'));

            await expect(authService.registerAgent(agentData, {} as any)).rejects.toThrow('Database error');
            expect(mockSession.abortTransaction).toHaveBeenCalled();
        });
    });

    describe('loginUser', () => {
        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should log in user successfully and return access token', async () => {
            const mockUser = {
                _id: 'userId',
                email: 'test@example.com',
                password: 'hashedPassword',
                isEmailVerified: true,
                security: 'securityId'
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);
            (createToken as jest.Mock).mockResolvedValue('accessToken');
            (createRefreshToken as jest.Mock).mockResolvedValue('refreshToken');
            (Security.findById as jest.Mock).mockResolvedValue({});

            const mockRes = {
                cookie: jest.fn()
            };

            const result = await authService.loginUser('test@example.com', 'password123', mockRes as any);

            expect(result).toHaveProperty('user');
            expect(result).toHaveProperty('accessToken', 'accessToken');
            expect(mockRes.cookie).toHaveBeenCalledWith('refreshToken', 'refreshToken', expect.any(Object));
        });

        it('should throw a 401 error for invalid email or password', async () => {
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);

            await expect(authService.loginUser('invalid@example.com', 'password123', {} as any)).rejects.toThrow(CustomError);
            await expect(authService.loginUser('invalid@example.com', 'password123', {} as any)).rejects.toHaveProperty('statusCode', 401);
        });

        it('should throw a 403 error if email is not verified', async () => {
            const mockUser = {
                _id: 'userId',
                email: 'test@example.com',
                password: 'hashedPassword',
                isEmailVerified: false,
                security: 'securityId'
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            await expect(authService.loginUser('test@example.com', 'password123', {} as any)).rejects.toThrow(CustomError);
            await expect(authService.loginUser('test@example.com', 'password123', {} as any)).rejects.toHaveProperty('statusCode', 403);
        });
    });

    describe('verifyOtp', () => {
        it('should verify OTP successfully', async () => {
            const mockUser = {
                _id: 'userId',
                security: 'securityId',
                isEmailVerified: false,
                save: jest.fn()
            };

            const mockSecurity = {
                otp: '123456',
                otpValidity: addMinutes(new Date(), 10),
                save: jest.fn()
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (Security.findById as jest.Mock).mockResolvedValue(mockSecurity);

            const result = await authService.verifyOtp('test@example.com', '123456');

            expect(result).toHaveProperty('message', 'OTP verified successfully');
            expect(mockUser.save).toHaveBeenCalled();
            expect(mockSecurity.save).toHaveBeenCalled();
        });

        it('should throw a 404 error if user is not found', async () => {
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);

            await expect(authService.verifyOtp('invalid@example.com', '123456')).rejects.toThrow(CustomError);
            await expect(authService.verifyOtp('invalid@example.com', '123456')).rejects.toHaveProperty('statusCode', 404);
        });

        it('should throw a 400 error for invalid OTP', async () => {
            const mockUser = {
                _id: 'userId',
                security: 'securityId',
                save: jest.fn()
            };

            const mockSecurity = {
                otp: '654321',
                otpValidity: addMinutes(new Date(), 10),
                save: jest.fn()
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (Security.findById as jest.Mock).mockResolvedValue(mockSecurity);

            await expect(authService.verifyOtp('test@example.com', '123456')).rejects.toThrow(CustomError);
            await expect(authService.verifyOtp('test@example.com', '123456')).rejects.toHaveProperty('statusCode', 400);
        });

        it('should throw a 400 error for expired OTP', async () => {
            const mockUser = {
                _id: 'userId',
                security: 'securityId',
                save: jest.fn()
            };

            const mockSecurity = {
                otp: '123456',
                otpValidity: addMinutes(new Date(), -10), // OTP is expired
                save: jest.fn()
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (Security.findById as jest.Mock).mockResolvedValue(mockSecurity);

            await expect(authService.verifyOtp('test@example.com', '123456')).rejects.toThrow(CustomError);
            await expect(authService.verifyOtp('test@example.com', '123456')).rejects.toHaveProperty('statusCode', 400);
        });
    });

    describe('resendOtp', () => {
        let mockSession: any;

        beforeEach(() => {
            mockSession = startSession();
        });

        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should resend OTP successfully', async () => {
            const mockUser = {
                email: 'test@example.com',
                security: 'securityId',
            };

            const mockSecurity = {
                otp: '123456',
                otpValidity: addMinutes(new Date(), 10),
                save: jest.fn()
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (Security.findById as jest.Mock).mockResolvedValue(mockSecurity);

            const mockRes = { cookie: jest.fn() };

            const result = await authService.resendOtp('test@example.com', mockRes as any);

            expect(result).toHaveProperty('message', 'OTP resent successfully');
            expect(mockSecurity.save).toHaveBeenCalled();
            expect(sendOtpEmail).toHaveBeenCalledWith('test@example.com', expect.any(String));
        });

        it('should throw 404 if user not found', async () => {
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);

            await expect(authService.resendOtp('invalid@example.com', {} as any)).rejects.toThrow(CustomError);
            await expect(authService.resendOtp('invalid@example.com', {} as any)).rejects.toHaveProperty('statusCode', 404);
        });

        it('should throw 404 if security record not found', async () => {
            const mockUser = {
                email: 'test@example.com',
                security: 'securityId',
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (Security.findById as jest.Mock).mockResolvedValue(null);

            await expect(authService.resendOtp('test@example.com', {} as any)).rejects.toThrow(CustomError);
            await expect(authService.resendOtp('test@example.com', {} as any)).rejects.toHaveProperty('statusCode', 404);
        });
    });

    describe('requestPasswordReset', () => {
        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should generate password reset token and send email', async () => {
            const mockUser = {
                email: 'test@example.com',
                security: 'securityId',
                save: jest.fn()
            };

            const mockSecurity = {
                passwordResetToken: 'resetToken',
                passwordResetExpires: addMinutes(new Date(), 60),
                save: jest.fn()
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (Security.findById as jest.Mock).mockResolvedValue(mockSecurity);
            (readFileSync as jest.Mock).mockReturnValue('privateKey');
            const signSpy = jest.spyOn(require('paseto').V4, 'sign').mockResolvedValue('resetToken');

            const result = await authService.requestPasswordReset('test@example.com');

            expect(result).toHaveProperty('message', 'Password reset email sent.');
            expect(sendPasswordResetEmail).toHaveBeenCalledWith('test@example.com', 'resetToken');
            expect(mockSecurity.save).toHaveBeenCalled();
        });

        it('should throw 404 if user not found', async () => {
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);

            await expect(authService.requestPasswordReset('invalid@example.com')).rejects.toThrow(CustomError);
            await expect(authService.requestPasswordReset('invalid@example.com')).rejects.toHaveProperty('statusCode', 404);
        });

        it('should throw 404 if security record not found', async () => {
            const mockUser = {
                email: 'test@example.com',
                security: 'securityId',
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (Security.findById as jest.Mock).mockResolvedValue(null);

            await expect(authService.requestPasswordReset('test@example.com')).rejects.toThrow(CustomError);
            await expect(authService.requestPasswordReset('test@example.com')).rejects.toHaveProperty('statusCode', 404);
        });
    });

    describe('resetPassword', () => {
        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should reset password successfully', async () => {
            const mockUser = {
                email: 'test@example.com',
                security: 'securityId',
                save: jest.fn()
            };

            const mockSecurity = {
                passwordResetToken: 'resetToken',
                passwordResetExpires: addMinutes(new Date(), 60),
                save: jest.fn()
            };

            (Security.findOne as jest.Mock).mockResolvedValue(mockSecurity);
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);
            (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
            (readFileSync as jest.Mock).mockReturnValue('publicKey');
            const verifySpy = jest.spyOn(require('paseto').V4, 'verify').mockResolvedValue({ email: 'test@example.com' });

            const result = await authService.resetPassword('resetToken', 'newPassword123');

            expect(result).toHaveProperty('message', 'Password has been reset successfully.');
            expect(mockUser.save).toHaveBeenCalled();
            expect(mockSecurity.save).toHaveBeenCalled();
        });

        it('should throw 400 if token is invalid or expired', async () => {
            const verifySpy = jest.spyOn(require('paseto').V4, 'verify').mockRejectedValue(new Error('Invalid token'));

            await expect(authService.resetPassword('invalidToken', 'newPassword123')).rejects.toThrow(CustomError);
            await expect(authService.resetPassword('invalidToken', 'newPassword123')).rejects.toHaveProperty('statusCode', 400);
        });

        it('should throw 404 if user not found', async () => {
            const mockSecurity = {
                passwordResetToken: 'resetToken',
                passwordResetExpires: addMinutes(new Date(), 60),
            };

            (Security.findOne as jest.Mock).mockResolvedValue(mockSecurity);
            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);

            await expect(authService.resetPassword('resetToken', 'newPassword123')).rejects.toThrow(CustomError);
            await expect(authService.resetPassword('resetToken', 'newPassword123')).rejects.toHaveProperty('statusCode', 404);
        });
    });

    describe('refreshToken', () => {
        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should refresh access token successfully', async () => {
            const mockSecurity = {
                refreshToken: 'validRefreshToken',
                refreshTokenExpires: addDays(new Date(), 7)
            };

            (Security.findOne as jest.Mock).mockResolvedValue(mockSecurity);
            (validateRefreshToken as jest.Mock).mockResolvedValue({ userId: 'userId', email: 'test@example.com' });
            (createToken as jest.Mock).mockResolvedValue('newAccessToken');

            const result = await authService.refreshToken('validRefreshToken');

            expect(result).toHaveProperty('accessToken', 'newAccessToken');
            expect(validateRefreshToken).toHaveBeenCalledWith('validRefreshToken');
        });

        it('should throw 401 if refresh token is invalid or expired', async () => {
            (Security.findOne as jest.Mock).mockResolvedValue(null);

            await expect(authService.refreshToken('invalidRefreshToken')).rejects.toThrow(CustomError);
            await expect(authService.refreshToken('invalidRefreshToken')).rejects.toHaveProperty('statusCode', 401);
        });
    });

    describe('handleGoogleAuth', () => {
        let mockSession: any;

        beforeEach(() => {
            mockSession = startSession();
        });

        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should create a new user using Google OAuth', async () => {
            const profile = {
                emails: [{ value: 'test@example.com' }],
                name: { givenName: 'John', familyName: 'Doe' },
                id: 'googleId'
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);
            (Security.prototype.save as jest.Mock).mockResolvedValue({});
            (User.prototype.save as jest.Mock).mockResolvedValue({});
            (Subscription.create as jest.Mock).mockResolvedValue([{ _id: 'subscriptionId' }]);
            (PersonalInfo.prototype.save as jest.Mock).mockResolvedValue({});

            const result = await authService.handleGoogleAuth(profile as any);

            expect(result).toHaveProperty('email', 'test@example.com');
            expect(result).toHaveProperty('googleId', 'googleId');
            expect(User.prototype.save).toHaveBeenCalled();
            expect(PersonalInfo.prototype.save).toHaveBeenCalled();
            expect(Security.prototype.save).toHaveBeenCalled();
        });

        it('should return existing user if they already exist', async () => {
            const profile = {
                emails: [{ value: 'existing@example.com' }],
                name: { givenName: 'John', familyName: 'Doe' },
                id: 'googleId'
            };

            const existingUser = {
                email: 'existing@example.com',
                googleId: 'googleId',
                security: 'securityId'
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(existingUser);

            const result = await authService.handleGoogleAuth(profile as any);

            expect(result).toEqual(existingUser);
            expect(PersonalInfo.findOne).toHaveBeenCalledWith({ email: 'existing@example.com' });
            expect(User.prototype.save).not.toHaveBeenCalled();
            expect(PersonalInfo.prototype.save).not.toHaveBeenCalled();
        });

        it('should throw error if Google profile does not contain an email', async () => {
            const profile = {
                emails: [],
                name: { givenName: 'John', familyName: 'Doe' },
                id: 'googleId'
            };

            await expect(authService.handleGoogleAuth(profile as any)).rejects.toThrow(CustomError);
            await expect(authService.handleGoogleAuth(profile as any)).rejects.toHaveProperty('statusCode', 400);
        });

        it('should handle transaction abort if there is an error', async () => {
            const profile = {
                emails: [{ value: 'test@example.com' }],
                name: { givenName: 'John', familyName: 'Doe' },
                id: 'googleId'
            };

            (PersonalInfo.findOne as jest.Mock).mockRejectedValue(new Error('Database Error'));

            await expect(authService.handleGoogleAuth(profile as any)).rejects.toThrow('Database Error');
            expect(mockSession.abortTransaction).toHaveBeenCalled();
        });
    });

    describe('handleGoogleSignIn', () => {
        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should return existing user by Google email', async () => {
            const profile = {
                emails: [{ value: 'test@example.com' }],
                name: { givenName: 'John', familyName: 'Doe' },
                id: 'googleId'
            };

            const mockUser = {
                email: 'test@example.com',
                googleId: 'googleId',
                security: 'securityId'
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(mockUser);

            const result = await authService.handleGoogleSignIn(profile as any);

            expect(result).toEqual(mockUser);
            expect(PersonalInfo.findOne).toHaveBeenCalledWith({ email: 'test@example.com' });
        });

        it('should return null if user is not found', async () => {
            const profile = {
                emails: [{ value: 'nonexistent@example.com' }],
                name: { givenName: 'John', familyName: 'Doe' },
                id: 'googleId'
            };

            (PersonalInfo.findOne as jest.Mock).mockResolvedValue(null);

            const result = await authService.handleGoogleSignIn(profile as any);

            expect(result).toBeNull();
        });

        it('should throw error if Google profile does not contain an email', async () => {
            const profile = {
                emails: [],
                name: { givenName: 'John', familyName: 'Doe' },
                id: 'googleId'
            };

            await expect(authService.handleGoogleSignIn(profile as any)).rejects.toThrow(CustomError);
            await expect(authService.handleGoogleSignIn(profile as any)).rejects.toHaveProperty('statusCode', 400);
        });
    });

    describe('logoutUser', () => {
        afterEach(() => {
            jest.clearAllMocks();
            jest.restoreAllMocks();
        });

        it('should log out user and clear refresh token', async () => {
            const mockSecurity = {
                refreshToken: 'validRefreshToken',
                refreshTokenExpires: addDays(new Date(), 7),
                save: jest.fn()
            };

            (Security.findOne as jest.Mock).mockResolvedValue(mockSecurity);

            const mockRes = {
                clearCookie: jest.fn()
            };

            const result = await authService.logoutUser('userId', mockRes as any);

            expect(result).toHaveProperty('message', 'User logged out successfully.');
            expect(mockRes.clearCookie).toHaveBeenCalledWith('refreshToken', expect.any(Object));
            expect(mockSecurity.save).toHaveBeenCalled();
        });

        it('should throw 404 if security record not found', async () => {
            (Security.findOne as jest.Mock).mockResolvedValue(null);

            const mockRes = { clearCookie: jest.fn() };

            await expect(authService.logoutUser('invalidUserId', mockRes as any)).rejects.toThrow(CustomError);
            await expect(authService.logoutUser('invalidUserId', mockRes as any)).rejects.toHaveProperty('statusCode', 404);
        });
    });
});
