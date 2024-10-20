import express from 'express';
import { generateWebhook, processWebhookLead } from '../controllers/WebhookController';
import { processWhatsAppResult } from '../controllers/WhatsAppWebhookController';
import { validateWebhookToken } from '../middlewares/WebhookMiddleware';

// Utility function to catch errors in async routes
const asyncHandler = (fn: Function) => (req: express.Request, res: express.Response, next: express.NextFunction) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// Create a new router
const router = express.Router();

// Route to generate a webhook for a user
router.post('/generate', asyncHandler(generateWebhook));

// Route to process leads via CRM webhook (secured by verify token)
router.post('/crm-lead', validateWebhookToken, asyncHandler(processWebhookLead));

// POST route to handle WhatsApp bot results
router.post('/whatsapp/webhook', asyncHandler(processWhatsAppResult));

export default router;
