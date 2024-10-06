import { config } from '../config/env';
import Joi from 'joi';


export const userSignupSchema = Joi.object({
    firstName: Joi.string().min(3).max(30).required(),
    lastName: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    dateOfBirth: Joi.date().optional(),
    phoneNumber1: Joi.string().min(9).max(13).pattern(/^\+\d+$/).required(), 
    countryCode: Joi.string().length(2).required(), 
    gender: Joi.string().valid('male', 'female', 'other').optional(), 
    password: Joi.string().min(8).required(),
    zipcode: Joi.number().optional(),
    recaptchaToken: config.nodeEnv === 'development' ? Joi.string().optional() : Joi.string().required(),
});


export const userLoginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    recaptchaToken: config.nodeEnv === 'development' ? Joi.string().optional() : Joi.string().required(),
});

export const emailVerificationSchema = Joi.object({
    email: Joi.string().required(),
    otp: Joi.string().required()
});

export const agentValidationSchema = Joi.object({
    role: Joi.string().required(),
    agentName: Joi.string().required(),
    language: Joi.string().required(),
    gender: Joi.string().valid('male', 'female').required(),
});

export const knowledgeBaseSchema = Joi.object({
    companyName: Joi.string().required(),
    description: Joi.string().optional(),
    industry: Joi.string().optional(),
    agentId: Joi.string().required(),
});

