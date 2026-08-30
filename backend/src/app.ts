import express, { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import cors from 'cors'
import compression from 'compression'
import { config } from './config'
import { logger } from './utils/logger'
import { AppError } from './utils/errors'
import { apiLimiter } from './middleware/rateLimit'
import authRoutes    from './routes/auth'
import licenseRoutes from './routes/license'
import adminRoutes   from './routes/admin'

const app = express()

app.set('trust proxy', 1)

app.use(helmet({
  hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: true,
  crossOriginResourcePolicy: { policy: 'same-origin' },
}))

const allowedOrigins = config.ALLOWED_ORIGINS.split(',').map(s => s.trim())
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) cb(null, true)
    else cb(new Error('Not allowed by CORS'))
  },
  credentials: true,
}))

app.use(compression())
app.use(express.json({ limit: '64kb' }))

app.use((req: Request, _res: Response, next: NextFunction) => {
  ;(req as Request & { id: string }).id = crypto.randomUUID()
  next()
})

app.use('/api/', apiLimiter)
app.use('/api/auth',     authRoutes)
app.use('/api/licenses', licenseRoutes)
app.use('/api/admin',    adminRoutes)

app.get('/health', (_req, res) => res.json({ status: 'ok', brand: 'Immortal Software' }))

app.use((_req, res) => res.status(404).json({ error: 'Not found' }))

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ error: err.message })
    return
  }
  logger.error('Unhandled error', { err })
  res.status(500).json({ error: 'Internal server error' })
})

export default app
