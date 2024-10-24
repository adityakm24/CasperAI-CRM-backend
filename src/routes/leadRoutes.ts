import { Router } from 'express';
import { addLead } from '../controllers/leadController';
import { authorize } from '../middlewares/authMiddleware'; // Replace authenticatePasetoToken with authorize
import { authorizeLeadCreation, validateLeadInput } from '../middlewares/leadMiddleware';

const router = Router();

// Apply token authentication before lead creation
router.post('/add-lead', authorize, authorizeLeadCreation, validateLeadInput, addLead);

export default router;
