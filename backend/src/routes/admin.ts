import { Router } from 'express'
import { requireAdmin } from '../middleware/auth'
import {
  handleListUsers,
  handleSuspendUser,
  handleActivateUser,
  handleListEvents,
  handleStats,
  handleListProducts,
  handleCreateProduct,
  handleCreatePlan,
} from '../controllers/adminController'

const router = Router()

router.use(requireAdmin)

router.get('/stats',                handleStats)
router.get('/users',                handleListUsers)
router.post('/users/:id/suspend',   handleSuspendUser)
router.post('/users/:id/activate',  handleActivateUser)
router.get('/events',               handleListEvents)
router.get('/products',             handleListProducts)
router.post('/products',            handleCreateProduct)
router.post('/plans',               handleCreatePlan)

export default router
