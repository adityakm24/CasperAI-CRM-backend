import { createLogger, format, transports } from 'winston';
import path from 'path';
import DailyRotateFile from 'winston-daily-rotate-file'; 

const logFormat = format.printf(({ timestamp, level, message, stack }) => {
  return `${timestamp} [${level}]: ${stack || message}`;
});

const dailyRotateFileTransport = new DailyRotateFile({
  filename: path.join(__dirname, '../../logs/%DATE%-combined.log'),
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m', 
  maxFiles: '14d', 
});

const logger = createLogger({
  level: 'info', 
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    format.splat(),
    format.json(),
    logFormat
  ),
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(), 
        logFormat
      ),
    }),
    dailyRotateFileTransport, 
    new transports.File({ filename: path.join(__dirname, '../../logs/error.log'), level: 'error' }) 
  ],
  exitOnError: false, 
});

export default logger;
