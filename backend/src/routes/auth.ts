import { Router } from 'express'
import { loginLimiter } from '../middleware/rateLimit'
import { requireAuth } from '../middleware/auth'
import {
  handleCredentialLogin,
  handleLicenseLogin,
  handleRefresh,
  handleLogout,
  handleMe,
} from '../controllers/authController'

const router = Router()

router.post('/login',         loginLimiter, handleCredentialLogin)
router.post('/login/license', loginLimiter, handleLicenseLogin)
router.post('/refresh',       handleRefresh)
router.post('/logout',        requireAuth(), handleLogout)
router.get('/me',             requireAuth(), handleMe)

export default router
