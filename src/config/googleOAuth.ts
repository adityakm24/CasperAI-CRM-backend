import { OAuth2Client } from 'google-auth-library';
import { Profile } from 'passport-google-oauth20';
import { config } from './env';

export const oAuth2Client = new OAuth2Client(
    config.googleClientId,
    config.googleClientSecret,
    config.googleCallbackUrl
);

export const getGoogleProfile = async (code: string): Promise<Profile> => {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const ticket = await oAuth2Client.verifyIdToken({
        idToken: tokens.id_token as string,
        audience: config.googleClientId
    });

    const payload = ticket.getPayload();
    if (!payload) {
        throw new Error('Unable to verify Google token');
    }

    const profile: Profile = {
        id: payload.sub,
        displayName: payload.name || '',
        name: {
            givenName: payload.given_name || 'Unknown',
            familyName: payload.family_name || 'User'
        },
        emails: [{
            value: payload.email || '',
            verified: payload.email_verified ?? false
        }],
        photos: [{ value: payload.picture || '' }],
        provider: 'google',
        _raw: JSON.stringify(payload),
        _json: payload,
        profileUrl: `https://plus.google.com/${payload.sub}`
    };
    

    return profile;
};
