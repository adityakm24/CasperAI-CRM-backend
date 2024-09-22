import mongoose, { Schema, Document } from 'mongoose';


export interface IColumn extends Document {
    title: string;
    created_at: Date;
    updated_at: Date;
}

const ColumnSchema: Schema = new Schema(
    {
        title: {
            type: String,
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

const Column = mongoose.model<IColumn>('Column', ColumnSchema);
export default Column;
