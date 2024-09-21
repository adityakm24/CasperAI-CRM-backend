import passport from 'passport';
import { Strategy as GoogleStrategy, Profile } from 'passport-google-oauth20';
import { config } from './env';
import { CustomError } from '../middlewares/errorHandler';
import logger from './logger';
import { handleGoogleAuth, handleGoogleSignIn } from '../services/authService';
import { readFileSync } from 'fs';
import { V4 as paseto } from 'paseto';
import { addDays } from 'date-fns';
import Security from '../models/Security';

import { Types } from 'mongoose';
import { IPersonalInfo } from '../models/PersonalInfo';

passport.use(new GoogleStrategy({
    clientID: config.googleClientId!,
    clientSecret: config.googleClientSecret!,
    callbackURL: config.googleCallbackUrl,
    scope: ['profile', 'email'],
},
    async (accessToken, refreshToken, profile: Profile, done) => {
        try {
            const user: IPersonalInfo = await handleGoogleSignIn(profile) || await handleGoogleAuth(profile);

            const userId = (user._id as Types.ObjectId).toString();

            const privateKey = readFileSync(config.pasetoKeys.privateKeyPath, 'utf8');
            const token = await paseto.sign({ userId, email: user.email }, privateKey, { expiresIn: '5h' });
            const refresh = await paseto.sign({ userId, email: user.email }, privateKey, { expiresIn: '7d' });

            const securityRecord = await Security.findById(user.security);
            if (securityRecord) {
                securityRecord.refreshToken = refresh;
                securityRecord.refreshTokenExpires = addDays(new Date(), 7);
                await securityRecord.save();
            }

            done(null, user.toObject(), { accessToken: token, refreshToken: refresh });
        } catch (error) {
            logger.error('Google OAuth error', { error: (error as Error).message });
            done(new CustomError('Authentication failed during Google login.', 500), false);
        }
    }
));
