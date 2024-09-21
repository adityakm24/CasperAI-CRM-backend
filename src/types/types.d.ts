import { IPersonalInfo } from '../models/PersonalInfo';
import 'express';

declare global {
  namespace Express {
    interface User extends IPersonalInfo {
      userId: any; 
      _id: string; 
    }
  }
}