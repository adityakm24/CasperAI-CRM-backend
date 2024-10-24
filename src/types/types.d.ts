import { IPersonalInfo } from '../models/PersonalInfo';
import { Types } from 'mongoose';
import 'express';

declare global {
  namespace Express {
    interface User {
      _id: Types.ObjectId;  // MongoDB document ID
      userId: Types.ObjectId;  // Reference to User model
      firstName: string;
      lastName: string;
      email: string;
      // other IPersonalInfo fields if needed
    }

    interface Request {
      user?: User;
    }
  }
}

// Add this to make it a module
export {};