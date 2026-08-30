import { Router } from 'express'
import { requireAuth, requireAdmin } from '../middleware/auth'
import { handleSecurityEvent, handleListEvents } from '../controllers/securityController'

const router = Router()

// Loader → backend: report a threat event (requires valid session token).
router.post('/event', requireAuth(), handleSecurityEvent)

// Admin: list security events with filters.
router.get('/events', requireAdmin, handleListEvents)

export default router
