import { Request, Response, NextFunction } from 'express';

// Utility function to handle async/await errors in controllers
export const httpHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch((error) => next(error));
  };
};
