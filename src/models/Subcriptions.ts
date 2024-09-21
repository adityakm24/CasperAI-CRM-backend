import { Schema, model, Document } from 'mongoose';

export interface ISubscription extends Document {
    plan: string;
    callMinutesQuota: number;
    callMinutesUsed: number;
    renewal: boolean;
    aiAgents: number;
    voices: number;
    languages: number;
    supportChannels: string[];
    customIntegrations: number;
    stripeCustomerId?: string | null;
    stripeSubscriptionId?: string | null;
}

const subscriptionSchema = new Schema<ISubscription>({
    plan: { type: String, required: true },
    callMinutesQuota: { type: Number, required: true },
    callMinutesUsed: { type: Number, default: 0 },
    renewal: { type: Boolean, default: true },
    aiAgents: { type: Number, required: true },
    voices: { type: Number, required: true },
    languages: { type: Number, required: true },
    supportChannels: [{ type: String }],
    customIntegrations: { type: Number, required: true },
    stripeCustomerId: { type: String, default: null },
    stripeSubscriptionId: { type: String, default: null }
});

const Subscription = model<ISubscription>('Subscription', subscriptionSchema);
export default Subscription;
