import { config } from '../config'
import { logger } from '../utils/logger'

/** Best-effort Discord (or generic) webhook for high-severity events. */
export async function notifyWebhook(payload: {
  title: string
  body: string
  severity?: number
  userId?: string
}): Promise<void> {
  const url = config.DISCORD_WEBHOOK_URL
  if (!url) return

  try {
    const content =
      `**${payload.title}**\n` +
      `${payload.body}` +
      (payload.userId ? `\nuser: \`${payload.userId}\`` : '') +
      (payload.severity != null ? `\nseverity: ${payload.severity}` : '')

    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: content.slice(0, 1800) }),
      signal: AbortSignal.timeout(4000),
    })
  } catch (err) {
    logger.warn('webhook notify failed', { err })
  }
}
