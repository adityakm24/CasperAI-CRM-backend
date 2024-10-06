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

export const sendOtpEmail = async (email: string, otp: string) => {
    const mailOptions = {
        from: '"Casper AI" <no-reply@casperai.co>',
        to: email,
        subject: 'Your Email Verification OTP',
        text: `Your OTP for email verification is: ${otp}. It is valid for 20 minutes.`,
        html: `<p>Your OTP for email verification is: <strong>${otp}</strong>. It is valid for 10 minutes.</p>`,
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