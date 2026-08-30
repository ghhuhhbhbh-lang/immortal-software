import { Router } from 'express'
import { requireAuth, requireAdmin } from '../middleware/auth'
import {
  dllUpload,
  handleUpload,
  handleSetLive,
  handleDeleteVersion,
  handleListVersions,
  handleCheck,
  handleDownload,
} from '../controllers/updateController'

const router = Router()

// ── Admin-only (requires ADMIN role) ──────────────────────────────
router.get(   '/admin/versions',              requireAdmin,                     handleListVersions)
router.post(  '/admin/upload',                requireAdmin, dllUpload.single('file'), handleUpload)
router.post(  '/admin/set-live/:version',     requireAdmin,                     handleSetLive)
router.delete('/admin/versions/:version',     requireAdmin,                     handleDeleteVersion)

// ── Client / Loader (requires valid access token) ─────────────────
router.get('/check',              requireAuth(),  handleCheck)
router.get('/download/:version',  requireAuth(),  handleDownload)

export default router
