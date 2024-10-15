import express from 'express';
import { generateWebhook, processWebhookLead } from '../controllers/WebhookController';
import { processWhatsAppResult } from '../controllers/WhatsAppWebhookController';
import { validateWebhookToken } from '../middlewares/WebhookMiddleware';

const router = express.Router();

// Route to generate a webhook for a user
router.post('/generate', generateWebhook);

// Route to process leads via CRM webhook (secured by verify token)
router.post('/crm-lead', validateWebhookToken, processWebhookLead);

// POST route to handle WhatsApp bot results
router.post('/whatsapp/webhook', processWhatsAppResult);


export default router;
