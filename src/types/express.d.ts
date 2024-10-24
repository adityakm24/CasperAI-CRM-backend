import { Types } from 'mongoose';

declare global {
  namespace Express {
    // Define our custom interface for the User
    interface User {
      _id: Types.ObjectId;
      userId: Types.ObjectId;
      firstName: string;
      lastName: string;
      email: string;
    }
  }
}