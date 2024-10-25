import { Response } from 'express';
import User from '../models/Users';
import PersonalInfo from '../models/PersonalInfo';
import Security from '../models/Security';
import Subscription from '../models/Subcriptions'; 
import { CustomError } from '../middlewares/errorHandler';
import { createToken, createRefreshToken, validateRefreshToken } from '../utils/tokenUtils';
import bcrypt from 'bcryptjs';
import { sendOtpEmail, sendPasswordResetEmail } from '../utils/email';
import { readFileSync } from 'fs';
import { V4 as paseto } from 'paseto';
import { config } from '../config/env';
import { addMinutes, addDays } from 'date-fns';
import logger from '../config/logger';
import { startSession } from 'mongoose';
import { randomBytes, randomInt, scryptSync } from 'crypto';
import { Profile } from 'passport-google-oauth20';


// Functions related to authentication like register, login, email verification, password reset (Only the AuthService class is Added here) Dont add anything else here 
// For updating user details, Profile Updates etc. Use userService.ts


export const registerAgent = async (agentData: any, res: Response) => {
    const session = await startSession();
    session.startTransaction();

    try {
        const { email, password, personalInfo, ...rest } = agentData;

        logger.info('Attempting to register user', { email });

        const existingPersonalInfo = await PersonalInfo.findOne({ email }).session(session);
        if (existingPersonalInfo) {
            logger.warn('User registration failed: Email already exists', { email });
            throw new CustomError('User with this email already exists.', 409);
        }

        const hashedPassword = await bcrypt.hash(password, 10);


        const otp = String(randomInt(100000, 999999));
        const otpValidity = addMinutes(new Date(), 20);
        
        const securityRecord = new Security({
            otp,
            otpValidity,
        });
        await securityRecord.save({ session });

        const defaultSubscription = await Subscription.create([{
            plan: 'Early Agent',
            callMinutesQuota: 500,
            callMinutesUsed: 0,
            renewal: true,
            aiAgents: 1,
            voices: 2,
            languages: 1,
            supportChannels: ['Email'],
            customIntegrations: 0,
            stripeCustomerId: '',
        }], { session });

        const newUser = new User({
            ...rest,
            role: 'Agent',
            isActive: true,
        });

        await newUser.save({ session });

        const personalInfoRecord = new PersonalInfo({
            ...personalInfo,
            email,
            password: hashedPassword,
            security: securityRecord._id,
            userId: newUser._id,
            isEmailVerified: false,
            subscriptionId: defaultSubscription[0]._id,
        });
        console.log('Personal Info Data:', personalInfo);
        await personalInfoRecord.save({ session });

        // Send OTP to the user's email
        await sendOtpEmail(email, otp);

        logger.info('User registered successfully, OTP sent', { email });

        const accessToken = await createToken({ userId: newUser._id, email });
        const refreshToken = await createRefreshToken({ userId: newUser._id, email });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: config.nodeEnv === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        securityRecord.refreshToken = refreshToken;
        securityRecord.refreshTokenExpires = addDays(new Date(), 7);
        await securityRecord.save({ session });

        await session.commitTransaction();

        const newUserResponse = {
            role: newUser.role,
        };

        const personalInfoResponse = {
            firstName: personalInfoRecord.firstName,
            lastName: personalInfoRecord.lastName,
            email: personalInfoRecord.email,
            phoneNumber1: personalInfoRecord.phoneNumber1,
            countryCode: personalInfoRecord.countryCode,
            isEmailVerified: personalInfoRecord.isEmailVerified,
        };

        return {
            agent: newUserResponse,
            personalInfo: personalInfoResponse,
            accessToken,
            redirectToSubcription: true,
        };
    } catch (error) {
        await session.abortTransaction();
        logger.error('Error during registration process', { error });
        throw error;
    } finally {
        session.endSession();
    }
};


export const loginUser = async (email: string, password: string, res: Response) => {
    logger.info('Attempting to log in user', { email });

    const user = await PersonalInfo.findOne({ email }).populate('security');

    if (!user) {
        logger.warn('Login failed: Invalid email or password', { email });
        throw new CustomError('Invalid email or password.', 401);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        logger.warn('Login failed: Invalid email or password', { email });
        throw new CustomError('Invalid email or password.', 401);
    }

    if (!user.isEmailVerified) {
        logger.warn('Login failed: Email not verified', { email });
        throw new CustomError('Please verify your email to log in.', 403);
    }

    logger.info('User logged in successfully', { email });

    const accessToken = await createToken({ userId: user._id, email: user.email });
    const refreshToken = await createRefreshToken({ userId: user._id, email: user.email });

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: config.nodeEnv === 'production', 
        sameSite: 'strict', 
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });


    const security = await Security.findById(user.security);

    if (!security) {
        logger.error('Security record not found for user', { userId: user._id });
        throw new CustomError('Security details not found.', 500);
    }

    security.refreshToken = refreshToken;
    security.refreshTokenExpires = addDays(new Date(), 7);
    await security.save();

    return {
        user,
        accessToken,
    };
};

export const verifyOtp = async (email: string, otp: string) => {
    try {
        logger.info('Attempting to verify OTP', { email, otp });

        const user = await PersonalInfo.findOne({ email }).populate('security');
        if (!user) {
            logger.warn('OTP verification failed: User not found', { email });
            throw new CustomError('User not found', 404);
        }

        const security = await Security.findById(user.security);
        if (!security) {
            logger.warn('OTP verification failed: Security details not found', { email });
            throw new CustomError('Security details not found', 404);
        }

        if (!security.otp || security.otp !== otp) {
            logger.warn('OTP verification failed: Invalid OTP', { email });
            throw new CustomError('Invalid OTP', 400);
        }

        if (!security.otpValidity || new Date() > security.otpValidity) {
            logger.warn('OTP verification failed: OTP expired', { email });
            throw new CustomError('OTP expired', 400);
        }

        user.isEmailVerified = true;
        security.otp = undefined;
        security.otpValidity = undefined;

        await user.save();
        await security.save();

        logger.info('OTP verified successfully', { userId: user._id });

        return { message: 'OTP verified successfully', userId: user._id };
    } catch (error: unknown) {
        if (error instanceof CustomError) {
            logger.error('Custom error during OTP verification', { error: error.message });
            throw error;
        } else if (error instanceof Error) {
            logger.error('Unexpected error during OTP verification', { error: error.message });
            throw new CustomError('An unexpected error occurred during OTP verification', 500);
        } else {
            logger.error('Unknown error type during OTP verification');
            throw new CustomError('An unknown error occurred', 500);
        }
    }
};

export const resendOtp = async (email: string, res: Response) => {
    const session = await startSession();
    session.startTransaction();
    
    try {
        const personalInfo = await PersonalInfo.findOne({ email }).session(session);
        if (!personalInfo) {
            throw new CustomError('User not found', 404);
        }

        const securityRecord = await Security.findById(personalInfo.security).session(session);
        if (!securityRecord) {
            throw new CustomError('Security record not found', 404);
        }

        const otp = String(randomInt(100000, 999999));
        const otpValidity = addMinutes(new Date(), 20);

        securityRecord.otp = otp;
        securityRecord.otpValidity = otpValidity;
        await securityRecord.save({ session });

        await sendOtpEmail(email, otp);

        logger.info('OTP resent successfully', { email });

        await session.commitTransaction();

        return { message: 'OTP resent successfully' };
    } catch (error) {
        await session.abortTransaction();
        logger.error('Error while resending OTP', { error });
        throw error;
    } finally {
        session.endSession();
    }
};


export const requestPasswordReset = async (email: string) => {
    const user = await PersonalInfo.findOne({ email }).populate('security');
    
    if (!user) {
        logger.warn('Password reset request failed: User not found', { email });
        throw new CustomError('User with this email does not exist.', 404);
    }

    const privateKey = readFileSync(config.pasetoKeys.privateKeyPath, 'utf8');
    const token = await paseto.sign({ email }, privateKey, { expiresIn: '1h' }); 

    const expires = addMinutes(new Date(), 60);

    const security = await Security.findById(user.security);
    if (!security) {
        logger.warn('Password reset failed: Security details not found', { email });
        throw new CustomError('Security details not found.', 404);
    }

    security.passwordResetToken = token;
    security.passwordResetExpires = expires;
    await security.save();

    await sendPasswordResetEmail(email, token);

    logger.info('Password reset token generated and email sent', { email });

    return { message: 'Password reset email sent.' };
};

export const resetPassword = async (token: string, newPassword: string) => {
    const publicKey = readFileSync(config.pasetoKeys.publicKeyPath, 'utf8');

    let payload;
    try {
        payload = await paseto.verify(token, publicKey);
    } catch (err) {
        logger.warn('Password reset failed: Invalid or expired token');
        console.log(err);
        throw new CustomError('Invalid or expired password reset token.', 400);
    }

    const security = await Security.findOne({ passwordResetToken: token });
    if (!security || !security.passwordResetExpires || new Date() > security.passwordResetExpires) {
        logger.warn('Password reset failed: Invalid or expired token');
        throw new CustomError('Invalid or expired password reset token.', 400);
    }

    const user = await PersonalInfo.findOne({ security: security._id });
    if (!user) {
        logger.warn('Password reset failed: User not found');
        throw new CustomError('User not found.', 404);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    security.passwordResetToken = '';
    security.passwordResetExpires = undefined;

    await user.save();
    await security.save();

    logger.info('Password reset successfully', { userId: user._id });

    return { message: 'Password has been reset successfully.' };
};

export const refreshToken = async (refreshToken: string) => {
    try {
        logger.info('Attempting to refresh access token');

        const security = await Security.findOne({ refreshToken });
        if (!security || !security.refreshTokenExpires || new Date() > security.refreshTokenExpires) {
            logger.warn('Refresh token is invalid or expired');
            throw new CustomError('Invalid or expired refresh token.', 401);
        }

        const payload = await validateRefreshToken(refreshToken);
        const accessToken = await createToken({ userId: payload.userId, email: payload.email });

        logger.info('Access token refreshed successfully', { userId: payload.userId });

        return { accessToken };
    } catch (error: any) {
        logger.error('Error during token refresh', { error: error.message });
        throw new CustomError(error.message || 'Token refresh failed.', error.statusCode || 500);
    }
};


const generatePassword = () => {
    const random = randomBytes(8).toString('hex');
    return scryptSync(random, 'salt', 16).toString('hex');
};

export const handleGoogleAuth = async (profile: Profile) => {
    const session = await startSession();
    session.startTransaction();

    try {
        logger.info('Handling Google OAuth', { profile });

        const email = profile.emails?.[0]?.value;
        if (!email) {
            logger.error('Google profile does not contain an email address');
            throw new CustomError('Google profile does not contain an email address', 400);
        }

        const firstName = profile.name?.givenName || 'Unknown';
        const lastName = profile.name?.familyName || 'User';

        let user = await PersonalInfo.findOne({ email }).session(session);

        if (!user) {
            logger.info('Creating new user', { email });

            const password = generatePassword();  
            const securityRecord = new Security({});
            await securityRecord.save({ session });

            const defaultSubscription = await Subscription.create([{
                plan: 'Early Agent',
                callMinutesQuota: 500,
                callMinutesUsed: 0,
                renewal: true,
                aiAgents: 1,
                voices: 6,
                languages: 3,
                supportChannels: ['Email'],
                customIntegrations: 0,
                stripeCustomerId: '',
            }], { session });

            const newUser = new User({
                isActive: true,
                role: 'Agent',
            });
            await newUser.save({ session });

            user = new PersonalInfo({
                firstName,
                lastName,
                email,
                googleId: profile.id,
                password,
                isEmailVerified: true,
                userId: newUser._id,
                security: securityRecord._id,
                phoneNumber1: '0000000000', 
                countryCode: 'NA',  
                subscriptionId: defaultSubscription[0]._id,
            });
            await user.save({ session });

            await session.commitTransaction();
            logger.info('Google OAuth successful, user created', { user });
            return user ;
        } else {
            logger.info('User already exists', { email });
            return user ;
        }
    } catch (error) {
        await session.abortTransaction();
        logger.error('Google OAuth error during transaction', { error: (error as Error).message, stack: (error as Error).stack });
        throw new CustomError('Authentication failed during Google login.', 500);
    } finally {
        session.endSession();
    }
};

export const handleGoogleSignIn = async (profile: Profile) => {
    try {
        const email = profile.emails?.[0]?.value;
        if (!email) throw new CustomError('Google profile does not contain an email address', 400);

        const user = await PersonalInfo.findOne({ email }).populate('security').exec();
        if (!user) return null;

        return user ; 
    } catch (error) {
        logger.error('Google SignIn error', { error: (error as Error).message, stack: (error as Error).stack });
        throw new CustomError('Authentication failed during Google login.', 500);
    }
};


export const logoutUser = async (userId: string, res: Response) => {
    try {
        logger.info('Attempting to log out user', { userId });

        const securityRecord = await Security.findOne({ userId });
        if (!securityRecord) {
            logger.warn('Logout failed: Security record not found', { userId });
            throw new CustomError('Security details not found.', 404);
        }

        securityRecord.refreshToken = undefined;
        securityRecord.refreshTokenExpires = undefined;
        await securityRecord.save();

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });

        logger.info('User logged out successfully', { userId });

        return { message: 'User logged out successfully.' };
    } catch (error) {
        logger.error('Error during logout', { error: (error as Error).message });
        throw new CustomError('Logout failed.', 500);
    }
};