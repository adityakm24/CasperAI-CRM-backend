import { Router, Request, Response, NextFunction } from 'express';
import * as authController from '../controllers/authController';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { authorize, authorizeRefreshToken } from '../middlewares/authMiddleware';
import { userSignupSchema, userLoginSchema, emailVerificationSchema } from '../utils/validationSchema';

// Utility function to catch errors in async routes
const asyncHandler = (fn: Function) => (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve(fn(req, res, next)).catch(next);

const router = Router();

// Register route
router.post('/register', validationMiddleware(userSignupSchema), asyncHandler(authController.register));

// Login route
router.post('/login', validationMiddleware(userLoginSchema), asyncHandler(authController.login));

// Email verification route
router.post('/verify-email', validationMiddleware(emailVerificationSchema),asyncHandler(authController.verifyOtp));

// Request password reset route
router.post('/request-password-reset', asyncHandler(authController.requestPasswordReset));

// Reset password route
router.post('/reset-password', asyncHandler(authController.resetPassword));

// Refresh token route
router.post('/refresh-token', authorizeRefreshToken, asyncHandler(authController.refreshAccessToken));

// Google authentication route
// Initiate Google OAuth route (redirects to Google)
router.get('/google', authController.initiateGoogleAuth);

// Google OAuth callback route
router.get('/google/callback', asyncHandler(authController.googleCallback));


//For Google Auth token verify
router.get('/verify-token', asyncHandler(authController.verifyToken));


export default router;
