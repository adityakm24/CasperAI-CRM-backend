import mongoose, { Schema, Document } from 'mongoose';


export interface IUser extends Document {
    personalInfoId: mongoose.Types.ObjectId; 
    role: string; 
    crm: string;
    crmIntegrationDetails: Record<string, any>; 
    isCaller: boolean;
    isActive: boolean;
    isWhatsAppVerified: boolean;
    whatsappBusinessId: string;
    whatsappToken: string;
    createdAt: Date;
    updatedAt: Date;
}


const UserSchema: Schema<IUser> = new Schema(
    {
        personalInfoId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'PersonalInfo',
            required: true,
        },
        role: {
            type: String,
            required: true,
        },
        crm: {
            type: String,
        },
        crmIntegrationDetails: {
            type: Schema.Types.Mixed, 
        },
        isCaller: {
            type: Boolean,
            default: false,
        },
        isActive: {
            type: Boolean,
            default: true,
        },
        isWhatsAppVerified: {
            type: Boolean,
            default: false,
        },
        whatsappBusinessId: {
            type: String,
        },
        whatsappToken: {
            type: String,
        },
        createdAt: {
            type: Date,
            default: Date.now,
        },
        updatedAt: {
            type: Date,
            default: Date.now,
        },
    },
    { timestamps: true }
);


const User = mongoose.model<IUser>('User', UserSchema);
export default User;
