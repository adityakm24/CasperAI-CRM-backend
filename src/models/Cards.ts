import mongoose, { Schema, Document } from 'mongoose';
import { IColumn } from './Columns';

export interface ICard extends Document {
    title: string;
    description: string;
    column_id: mongoose.Types.ObjectId | IColumn;
    created_at: Date;
    updated_at: Date;
}

const CardSchema: Schema = new Schema(
    {
        title: {
            type: String,
            required: true,
        },
        description: {
            type: String,
            required: true,
        },
        column_id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Column', 
            required: true,
        },
        created_at: {
            type: Date,
            default: Date.now,
        },
        updated_at: {
            type: Date,
            default: Date.now,
        },
    },
    { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } } 
);

const Card = mongoose.model<ICard>('Card', CardSchema);
export default Card;
