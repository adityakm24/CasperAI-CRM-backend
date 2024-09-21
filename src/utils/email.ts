import nodemailer from 'nodemailer';
import { config } from '../config/env';

const transporter = nodemailer.createTransport({
    host: config.mailHost,
    port: config.mailPort,
    auth: {
        user: config.mailUser,
        pass: config.mailPass,
    },
});

export const sendVerificationEmail = async (email: string, token: string) => {
    const verificationLink = `${config.frontendUrl}/verify-email?token=${token}`;
    const mailOptions = {
        from: '"Casper AI" <no-reply@casperai.co>',
        to: email,
        subject: 'Email Verification',
        text: `Please verify your email by clicking the link: ${verificationLink}`,
        html: `<p>Please verify your email by clicking the link below:</p><a href="${verificationLink}">${verificationLink}</a>`,
    };

    await transporter.sendMail(mailOptions);
};


export const sendPasswordResetEmail = async (email: string, token: string) => {
    const resetLink = `${config.frontendUrl}/reset-password?token=${token}`;
    const mailOptions = {
        from: '"casper AI" <no-reply@casperai.co>',
        to: email,
        subject: 'Password Reset Request',
        text: `You requested a password reset. Please reset your password by clicking the link: ${resetLink}`,
        html: `<p>You requested a password reset. Please reset your password by clicking the link below:</p><a href="${resetLink}">${resetLink}</a>`,
    };

    await transporter.sendMail(mailOptions);
};