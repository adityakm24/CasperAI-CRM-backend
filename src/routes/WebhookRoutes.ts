import express from 'express';
import { generateWebhook, processWebhookLead } from '../controllers/WebhookController';
import { validateWebhookToken } from '../middlewares/WebhookMiddleware';

const router = express.Router();

// Route to generate a webhook for a user
router.post('/generate', generateWebhook);

// Route to process leads via CRM webhook (secured by verify token)
router.post('/', validateWebhookToken, processWebhookLead);

export default router;
