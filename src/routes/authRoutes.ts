import { Router, Request, Response } from 'express';
import * as authController from '../controllers/authController';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { authorize, authorizeRefreshToken } from '../middlewares/authMiddleware';
import { userSignupSchema, userLoginSchema } from '../utils/validationSchema';
import passport from 'passport';



const router = Router();

router.post('/register', validationMiddleware(userSignupSchema), authController.register);

router.post('/login', validationMiddleware(userLoginSchema), authController.login);

router.get('/verify-email', authController.verifyEmail);

router.post('/request-password-reset', authController.requestPasswordReset);

router.post('/reset-password', authController.resetPassword);

router.post('/refresh-token', authorizeRefreshToken, authController.refreshAccessToken);

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', authController.googleCallback);


export default router;
