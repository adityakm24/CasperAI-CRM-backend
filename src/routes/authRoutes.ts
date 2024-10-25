import { Router, Request, Response, NextFunction } from 'express';
import * as authController from '../controllers/authController';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { authorize, authorizeRefreshToken } from '../middlewares/authMiddleware';
import { userSignupSchema, userLoginSchema, emailVerificationSchema , resendOtpSchema } from '../utils/validationSchema';

const asyncHandler = (fn: Function) => (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve(fn(req, res, next)).catch(next);

const router = Router();

router.post('/register', validationMiddleware(userSignupSchema), asyncHandler(authController.register));

router.post('/login', validationMiddleware(userLoginSchema), asyncHandler(authController.login));

router.post('/verify-email', validationMiddleware(emailVerificationSchema),asyncHandler(authController.verifyOtp));

router.post('/resend-otp', authorize, validationMiddleware(resendOtpSchema), asyncHandler(authController.resendOtp));

router.post('/request-password-reset', asyncHandler(authController.requestPasswordReset));

router.post('/reset-password', asyncHandler(authController.resetPassword));

router.post('/refresh-token', authorizeRefreshToken, asyncHandler(authController.refreshAccessToken));

router.get('/google', authController.initiateGoogleAuth);

router.get('/google/callback', asyncHandler(authController.googleCallback));

router.get('/verify-token', asyncHandler(authController.verifyToken));

router.post('/logout', authorize, asyncHandler(authController.logout));


export default router;
