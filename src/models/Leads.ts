import mongoose, { Schema, Document } from 'mongoose';

// Define the interface for a Lead document
export interface ILead extends Document {
    firstName: string;
    lastName: string;
    phoneNumber: string;
    crmIdentifier: string;
    status: 'fresh' | 'qualified' | 'unqualified';
    notes: string;
    userId: mongoose.Types.ObjectId; // Foreign key to users collection
    propertyInterest: string;
    createdAt: Date;
    updatedAt: Date;
}

// Define the schema for Lead
const LeadSchema: Schema = new Schema(
    {
        firstName: {
            type: String,
            required: true,
        },
        lastName: {
            type: String,
            required: true,
        },
        phoneNumber: {
            type: String,
            required: true,
        },
        crmIdentifier: {
            type: String,
            required: true,
        },
        status: {
            type: String,
            enum: ['fresh', 'qualified', 'unqualified'],
            required: true,
        },
        notes: {
            type: String,
            required: false,
        },
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },
        propertyInterest: {
            type: String,
            required: false,
        },
    },
    {
        timestamps: true, // Automatically adds createdAt and updatedAt fields
    }
);

// Create the Lead model
const Lead = mongoose.model<ILead>('Lead', LeadSchema);

export default Lead;
