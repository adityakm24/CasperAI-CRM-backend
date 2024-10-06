import {config}  from './env';
import helmet from 'helmet';

export const helmetConfig = () => {
    const isProduction = config.nodeEnv === 'production';

    return helmet({
        contentSecurityPolicy: isProduction
            ? {
                useDefaults: true,
                directives: {
                    'default-src': ["'self'"],
                    'script-src': [
                        "'self'",
                        "'nonce-<generated-nonce>'", 
                        'https://js.stripe.com',
                    ],
                    'frame-src': ['https://js.stripe.com'],
                    'connect-src': [
                        "'self'",
                        'https://api.stripe.com',
                    ],
                    'img-src': ["'self'", 'data:', 'https://*.stripe.com'],
                    'style-src': ["'self'", "'unsafe-inline'"],
                },
            }
            : false,
        frameguard: { action: isProduction ? 'deny' : 'sameorigin' }, 
        referrerPolicy: { policy: isProduction ? 'strict-origin-when-cross-origin' : 'no-referrer' },
        noSniff: true,  
        ieNoOpen: true, 
        xssFilter: true, 
        ...(isProduction && {
            strictTransportSecurity: {
                maxAge: 63072000, // 2 years 
                includeSubDomains: true,
                preload: true,
            },
        }),
    });
};
