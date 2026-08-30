import { Router } from 'express'
import { requireAdmin } from '../middleware/auth'
import {
  handleCreateLicenses,
  handleListLicenses,
  handleSuspend,
  handleRevoke,
  handleExtend,
  handleResetDevices,
} from '../controllers/licenseController'

const router = Router()

router.post('/',                    requireAdmin, handleCreateLicenses)
router.get('/',                     requireAdmin, handleListLicenses)
router.post('/:id/suspend',         requireAdmin, handleSuspend)
router.post('/:id/revoke',          requireAdmin, handleRevoke)
router.post('/:id/extend',          requireAdmin, handleExtend)
router.post('/:id/reset-devices',   requireAdmin, handleResetDevices)

export default router
