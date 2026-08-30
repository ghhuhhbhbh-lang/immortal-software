import 'dotenv/config'
import app from './app'
import { config } from './config'
import { prisma } from './db'
import { logger } from './utils/logger'
import { purgeExpiredRecords } from './services/tokenService'

async function start(): Promise<void> {
  await prisma.$connect()
  logger.info('Database connected — Immortal Software API starting')

  setInterval(() => {
    purgeExpiredRecords().catch((err: unknown) => logger.error('Purge failed', { err }))
  }, 10 * 60 * 1000)

  const server = app.listen(config.PORT, () => {
    logger.info(
      `Immortal Software API v${config.APP_VERSION} on :${config.PORT} [${config.NODE_ENV}]`
    )
  })

  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`${signal} received — shutting down gracefully`)
    server.close(async () => {
      await prisma.$disconnect()
      logger.info('Shutdown complete')
      process.exit(0)
    })
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT',  () => shutdown('SIGINT'))
}

start().catch((err: unknown) => {
  console.error('Fatal startup error:', err)
  process.exit(1)
})
