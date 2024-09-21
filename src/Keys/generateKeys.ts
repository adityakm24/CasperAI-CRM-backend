import {  existsSync, writeFileSync } from 'fs';
import { generateKeyPairSync } from 'crypto';
import { join } from 'path';
import logger from '../config/logger'; 

const privateKeyPath = join(__dirname, '..', 'Keys', 'private_key.pem'); 
const publicKeyPath = join(__dirname, '..', 'Keys', 'public_key.pem');

export const generateKeys = () => {
    if (!existsSync(privateKeyPath) || !existsSync(publicKeyPath)) {
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
    } else {
        logger.info('Key pair already exists, skipping generation');
    }
};
