import { Schema, model, Document, Types } from 'mongoose';

export interface IPersonalInfo extends Document {
    firstName: string;
    lastName: string;
    email: string;
    dateOfBirth: Date;
    phoneNumber1: string;
    countryCode: string;
    gender: string;
    userId: Types.ObjectId;
    googleId: string;
    password: string;
    zipcode: number;
    isEmailVerified: boolean;
    security: Types.ObjectId;
    subscriptionId: Types.ObjectId;
}

const personalInfoSchema = new Schema<IPersonalInfo>({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    dateOfBirth: { type: Date },
    phoneNumber1: { type: String, required: true },
    countryCode: { type: String, required: true },
    gender: { type: String },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    googleId: { type: String, unique: true, sparse: true },
    password: { type: String, required: true },
    zipcode: { type: Number },
    isEmailVerified: { type: Boolean, default: false },
    security: { type: Schema.Types.ObjectId, ref: 'Security', required: true },
    subscriptionId: { type: Schema.Types.ObjectId, ref: 'Subscription', required: true },

}, { timestamps: true });

export default model<IPersonalInfo>('PersonalInfo', personalInfoSchema);
