import express, { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import cors from 'cors'
import compression from 'compression'
import { config } from './config'
import { prisma } from './db'
import { logger } from './utils/logger'
import { AppError } from './utils/errors'
import { apiLimiter } from './middleware/rateLimit'
import authRoutes    from './routes/auth'
import licenseRoutes from './routes/license'
import adminRoutes   from './routes/admin'
import updateRoutes   from './routes/update'
import securityRoutes from './routes/security'

const app = express()

app.set('trust proxy', 1)

app.use(helmet({
  hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
}))

app.use((req: Request, res: Response, next: NextFunction) => {
  const id = crypto.randomUUID()
  ;(req as Request & { id: string }).id = id
  res.setHeader('X-Request-Id', id)
  res.setHeader('X-Immortal-Version', config.APP_VERSION)
  next()
})

const allowedOrigins = config.ALLOWED_ORIGINS.split(',').map(s => s.trim())
app.use(cors({
  origin: (origin, cb) => {
    // file:// / WebView2 / local tooling often send null or no Origin
    if (!origin || origin === 'null' || allowedOrigins.includes(origin)) {
      cb(null, true)
      return
    }
    if (/^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/i.test(origin)) {
      cb(null, true)
      return
    }
    if (/^https?:\/\/immortal\.loader$/i.test(origin)) {
      cb(null, true)
      return
    }
    cb(new Error('Not allowed by CORS'))
  },
  credentials: true,
}))

app.use(compression())
app.use(express.json({ limit: '64kb' }))

app.use('/api/', apiLimiter)
app.use('/api/auth',     authRoutes)
app.use('/api/licenses', licenseRoutes)
app.use('/api/admin',    adminRoutes)
app.use('/api/update',   updateRoutes)
app.use('/api/security', securityRoutes)

const startedAt = Date.now()

app.get('/health', async (_req, res) => {
  let db: 'ok' | 'down' = 'ok'
  try {
    await prisma.$queryRaw`SELECT 1`
  } catch {
    db = 'down'
  }
  const status = db === 'ok' ? 'ok' : 'degraded'
  res.status(db === 'ok' ? 200 : 503).json({
    status,
    brand: 'Immortal Software',
    version: config.APP_VERSION,
    env: config.NODE_ENV,
    uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
    db,
    time: new Date().toISOString(),
  })
})

app.get('/metrics', (_req, res) => {
  const mem = process.memoryUsage()
  const uptime = Math.floor((Date.now() - startedAt) / 1000)
  res.type('text/plain').send(
    [
      `# HELP immortal_uptime_seconds Process uptime`,
      `# TYPE immortal_uptime_seconds gauge`,
      `immortal_uptime_seconds ${uptime}`,
      `# HELP immortal_rss_bytes Resident set size`,
      `# TYPE immortal_rss_bytes gauge`,
      `immortal_rss_bytes ${mem.rss}`,
      `# HELP immortal_heap_used_bytes Heap used`,
      `# TYPE immortal_heap_used_bytes gauge`,
      `immortal_heap_used_bytes ${mem.heapUsed}`,
      `# HELP immortal_heap_total_bytes Heap total`,
      `# TYPE immortal_heap_total_bytes gauge`,
      `immortal_heap_total_bytes ${mem.heapTotal}`,
      `# HELP immortal_external_bytes External memory`,
      `# TYPE immortal_external_bytes gauge`,
      `immortal_external_bytes ${mem.external}`,
      `# HELP immortal_info Build info`,
      `# TYPE immortal_info gauge`,
      `immortal_info{version="${config.APP_VERSION}",env="${config.NODE_ENV}"} 1`,
    ].join('\n') + '\n'
  )
})

app.use((_req, res) => res.status(404).json({ error: 'Not found' }))

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof Error && err.message === 'Not allowed by CORS') {
    res.status(403).json({ error: 'Origin not allowed' })
    return
  }
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ error: err.message })
    return
  }
  logger.error('Unhandled error', { err })
  res.status(500).json({ error: 'Something went wrong on our side. Try again' })
})

export default app
