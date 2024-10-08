import mongoose, { Schema, Document } from 'mongoose';


export interface IUser extends Document {
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
    kanbanBoard: mongoose.Types.ObjectId[]; 
}

const UserSchema: Schema<IUser> = new Schema(
    {
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
        kanbanBoard: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Column', 
            },
        ],
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
