import { Router } from 'express'
import { loginLimiter } from '../middleware/rateLimit'
import { requireAuth } from '../middleware/auth'
import {
  handleCredentialLogin,
  handleLicenseLogin,
  handleRefresh,
  handleLogout,
  handleMe,
  handleHeartbeat,
  handleAttest,
  handleClientThreat,
} from '../controllers/authController'

const router = Router()

router.post('/login',         loginLimiter, handleCredentialLogin)
router.post('/login/license', loginLimiter, handleLicenseLogin)
router.post('/refresh',       handleRefresh)
router.post('/logout',        requireAuth(), handleLogout)
router.get('/me',             requireAuth(), handleMe)
router.post('/heartbeat',     requireAuth(), handleHeartbeat)
router.post('/attest',        requireAuth(), handleAttest)
router.post('/threat',        requireAuth(), handleClientThreat)

export default router
