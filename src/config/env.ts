import dotenv from 'dotenv';

dotenv.config();

export const config = {
    port :  process.env.PORT || 3000,
    pasetoKeys : { 
        secretKey: process.env.SECRET_KEY ,
        publicKeyPath: process.env.PASETO_PUBLIC_KEY_PATH || './src/Keys/public_key.pem',
        privateKeyPath: process.env.PASETO_PRIVATE_KEY_PATH || './src/Keys/private_key.pem',
    },
    mongoUri: process.env.MONGODB_URI || '',
    frontendUrl: process.env.FRONTEND_URL,
    googleClientId: process.env.GOOGLE_CLIENT_ID || '',
    googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    googleCallbackUrl: process.env.GOOGLE_CALLBACK_URL || '',
    recaptchaSecretKey: process.env.RECAPTCHA_SECRET_KEY,
    mailHost: process.env.MAIL_HOST,
    mailPort: Number(process.env.MAIL_PORT),
    mailUser: process.env.MAIL_USER,
    mailPass: process.env.MAIL_PASS,
}