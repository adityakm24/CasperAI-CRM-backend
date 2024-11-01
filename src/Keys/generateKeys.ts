import { existsSync, writeFileSync } from 'fs';
import { generateKeyPairSync } from 'crypto';
import { join } from 'path';
import logger from '../config/logger';

const privateKeyPath = join(__dirname, '..', 'Keys', 'private_key.pem');
const publicKeyPath = join(__dirname, '..', 'Keys', 'public_key.pem');

export const generateKeys = () => {
    logger.info('Running key generation check...'); 
    if (!existsSync(privateKeyPath) || !existsSync(publicKeyPath)) {
        logger.info('Keys do not exist. Generating new key pair...');

        try {
            const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem',
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem',
                },
            });

            writeFileSync(privateKeyPath, privateKey, { encoding: 'utf8' });
            writeFileSync(publicKeyPath, publicKey, { encoding: 'utf8' });

            logger.info('ed25519 key pair generated successfully');
        } catch (error) {
            if (error instanceof Error) {
                logger.error('Failed to generate or write keys', { error: error.message });
            } else {
                logger.error('Failed to generate or write keys', { error: String(error) });
            }
        }
    } else {
        logger.info('Key pair already exists, skipping generation');
    }
};
