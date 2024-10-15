import mongoose, { Schema, Document } from 'mongoose';

// Define the interface for a Webhook document
export interface IWebhook extends Document {
    userId: mongoose.Types.ObjectId;
    verifyToken: string;
}

// Define the schema for Webhook
const WebhookSchema: Schema = new Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    verifyToken: {
        type: String,
        required: true,
        unique: true, // Ensure the verify token is unique
    },
});

const Webhook = mongoose.model<IWebhook>('Webhook', WebhookSchema);
export default Webhook;
