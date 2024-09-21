import { V4 } from 'paseto';
import { readFileSync } from 'fs';
import { config } from '../config/env';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';

const secretKey = config.pasetoKeys.secretKey;
if (!secretKey) {
    throw new CustomError('SECRET_KEY is not defined in the environment variables', 500);
}


export async function createToken(data: Record<string, any>): Promise<string> {
    try {

        data.secret_key = secretKey;
        const privateKey = readFileSync(config.pasetoKeys.privateKeyPath, 'utf8');
        const token = await V4.sign(data, privateKey, { expiresIn: '500m' });

        logger.info('PASETO token created successfully', { token });
        return token;
    } catch (err) {
        logger.error('Error creating PASETO token', { error: err });
        throw new CustomError('Failed to create PASETO token', 500);
    }
}

export async function createRefreshToken(data: Record<string, any>): Promise<string> {
    try {
        data.secret_key = secretKey;
        const privateKey = readFileSync(config.pasetoKeys.privateKeyPath, 'utf8');
        const refreshToken = await V4.sign(data, privateKey, { expiresIn: '7d' });

        logger.info('PASETO refresh token created successfully', { refreshToken });
        return refreshToken;
    } catch (err) {
        logger.error('Error creating PASETO refresh token', { error: err });
        throw new CustomError('Failed to create PASETO refresh token', 500);
    }
}

export async function validateToken(token: string): Promise<any> {
    try {
        const publicKey = readFileSync(config.pasetoKeys.publicKeyPath, 'utf8');
        const payload = await V4.verify(token, publicKey);
        logger.info('PASETO token validated successfully', { token });
        return payload;
    } catch (err) {
        logger.error('Error validating PASETO token', { error: err });
        throw new CustomError('Invalid or expired token', 401);
    }
}

export async function validateRefreshToken(refreshToken: string): Promise<any> {
    try {
        const publicKey = readFileSync(config.pasetoKeys.publicKeyPath, 'utf8');
        const payload = await V4.verify(refreshToken, publicKey);

        if (payload.type !== 'refresh') {
            throw new CustomError('Invalid token type', 401);
        }

        logger.info('PASETO refresh token validated successfully', { refreshToken });
        return payload;
    } catch (err) {
        logger.error('Error validating PASETO refresh token', { error: err });
        throw new CustomError('Invalid or expired refresh token', 401);
    }
}
