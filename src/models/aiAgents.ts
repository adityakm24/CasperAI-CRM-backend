import mongoose, { Schema, Document } from 'mongoose';


export interface IAIAgent extends Document {
    userId: mongoose.Types.ObjectId; 
    name: string;
    status: string;
    configuration: Record<string, any>; 
    createdAt: Date;
    updatedAt: Date;
}

const AIAgentSchema: Schema<IAIAgent> = new Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },
        name: {
            type: String,
            required: true,
        },
        status: {
            type: String,
            required: true,
        },
        configuration: {
            type: Schema.Types.Mixed, 
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


const AIAgent = mongoose.model<IAIAgent>('AIAgent', AIAgentSchema);
export default AIAgent;
