import { V4 } from 'paseto';
import { readFileSync } from 'fs';
import { config } from '../config/env';
import { CustomError } from '../middlewares/errorHandler';
import logger from '../config/logger';

const privateKey = readFileSync(config.pasetoKeys.privateKeyPath, 'utf8');
const publicKey = readFileSync(config.pasetoKeys.publicKeyPath, 'utf8');
const secretKey = config.pasetoKeys.secretKey;

if (!secretKey) {
    throw new CustomError('SECRET_KEY is not defined in the environment variables', 500);
}

async function createPasetoToken(data: Record<string, any>, expiresIn: string): Promise<string> {
    try {
        const token = await V4.sign(data, privateKey, { expiresIn });
        logger.info('PASETO token created successfully', { token });
        return token;
    } catch (err) {
        logger.error('Error creating PASETO token', { error: err });
        throw new CustomError('Failed to create PASETO token', 500);
    }
}

export async function createToken(data: Record<string, any>): Promise<string> {
    const payload = { ...data, secret_key: secretKey }; 
    return createPasetoToken(payload, '500m');
}

export async function createRefreshToken(data: Record<string, any>): Promise<string> {
    const payload = { ...data, type: 'refresh', secret_key: secretKey };  
    return createPasetoToken(payload, '7d');
}

export async function validateToken(token: string): Promise<any> {
    try {
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
