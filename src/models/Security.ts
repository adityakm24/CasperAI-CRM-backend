import { Schema, model, Document } from 'mongoose';

export interface ISecurity extends Document {
    refreshToken?: string;
    refreshTokenExpires?: Date;
    passwordResetToken?: string;
    passwordResetExpires?: Date;
    otp?: string;
    otpValidity?: Date;
}

const securitySchema = new Schema<ISecurity>({
    refreshToken: { type: String, default: undefined },
    refreshTokenExpires: { type: Date, default: undefined },
    passwordResetToken: { type: String, default: undefined },
    passwordResetExpires: { type: Date, default: undefined },
    otp: { type: String, default: undefined },
    otpValidity: { type: Date, default: undefined },
});

export default model<ISecurity>('Security', securitySchema);
