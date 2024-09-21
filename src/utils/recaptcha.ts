import axios from 'axios';
import { config } from '../config/env';
import { CustomError } from '../middlewares/errorHandler';

export const verifyRecaptcha = async (token: string) => {
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
            params: {
                secret: config.recaptchaSecretKey,
                response: token,
            },
        });

        const { success, score } = response.data;

        if (!success || score < 0.5) {
            throw new CustomError('Failed reCAPTCHA verification.', 400);
        }

        return true;
    } catch (error) {
        throw new CustomError('Failed to verify reCAPTCHA.', 400);
    }
};
