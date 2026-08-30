import { Request, Response } from 'express'
import { prisma } from '../db'
import { logger } from '../utils/logger'
import { AuthenticatedRequest } from '../types'
import https from 'https'

// ──────────────────── types ────────────────────

interface SecurityEventPayload {
  eventType:     string
  severity:      string
  reason:        string
  loaderVersion: string
  fingerprint:   string
  revoke:        boolean
}

const SEVERITY_RANK: Record<string, number> = {
  INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3,
}

const ALLOWED_EVENTS = new Set([
  'DEBUGGER_DETECTED', 'FILE_INTEGRITY_FAILURE', 'SECURITY_CODE_PATCH_DETECTED',
  'SECURITY_MODULE_TAMPER', 'LICENSE_AUTH_BYPASS_ATTEMPT', 'INVALID_SIGNATURE',
  'DEVICE_CHANGE_DETECTED', 'NEW_INSTALLATION_DETECTED', 'HEARTBEAT_TIMEOUT',
  'LOADER_VERSION_TAMPER', 'HOOK_DETECTED', 'ANTI_VM', 'ANTI_DEBUG', 'ANTI_TAMPER',
  'ANTI_DUMP', 'ANTI_INJECT', 'PIPE_LOST', 'SESSION_REVOKED', 'INTEGRITY',
])

// ──────────────────── Discord ────────────────────

function discordColor(severity: string): number {
  const map: Record<string, number> = {
    CRITICAL: 0xff0000, HIGH: 0xff6600, MEDIUM: 0xffcc00, INFO: 0x00aaff,
  }
  return map[severity] ?? 0x808080
}

function discordEmoji(severity: string): string {
  const map: Record<string, string> = {
    CRITICAL: '🚨', HIGH: '⚠️', MEDIUM: '🟡', INFO: 'ℹ️',
  }
  return map[severity] ?? '🔵'
}

async function sendDiscordAlert(payload: SecurityEventPayload, licensePrefix: string, userId?: string | null): Promise<void> {
  const url = process.env.DISCORD_WEBHOOK_URL
  if (!url || !url.includes('discord.com/api/webhooks/')) return

  const action = payload.revoke ? 'LICENSE REVOKED' : 'EVENT LOGGED'

  const embed = {
    embeds: [{
      title: `${discordEmoji(payload.severity)} IMMORTAL — Security Alert`,
      description: 'A security event was detected and processed by the backend.',
      color: discordColor(payload.severity),
      fields: [
        { name: 'Event Type',     value: payload.eventType,     inline: true },
        { name: 'Severity',       value: payload.severity,       inline: true },
        { name: 'Loader Version', value: payload.loaderVersion || '—', inline: true },
        { name: 'License Prefix', value: licensePrefix || '—',  inline: true },
        { name: 'User ID',        value: userId ? userId.slice(0, 8) + '…' : '—', inline: true },
        { name: 'Device Fingerprint', value: payload.fingerprint?.slice(0, 16) || '—', inline: true },
        { name: 'Action',         value: action,                 inline: false },
        { name: 'Reason',         value: payload.reason || '—', inline: false },
        { name: 'Time (UTC)',     value: new Date().toISOString(), inline: false },
      ],
      footer: { text: 'Immortal Software · Backend Security System' },
    }],
  }

  const body = JSON.stringify(embed)
  const urlObj = new URL(url)

  await new Promise<void>((resolve) => {
    const req = https.request(
      { hostname: urlObj.hostname, path: urlObj.pathname + urlObj.search,
        method: 'POST', headers: { 'Content-Type': 'application/json',
                                   'Content-Length': Buffer.byteLength(body) } },
      (res) => { res.resume(); resolve() }
    )
    req.on('error', () => resolve()) // never crash on webhook failure
    req.write(body)
    req.end()
  })
}

// ──────────────────── controller ────────────────────

// POST /api/security/event
// Receives a threat event from the running loader.
// Requires valid Bearer JWT — so a compromised loader that can no longer
// authenticate cannot fake events (and they're ignored if so).
export async function handleSecurityEvent(req: Request, res: Response) {
  const user = (req as AuthenticatedRequest).user

  const body = req.body as Partial<SecurityEventPayload>

  const eventType     = (body.eventType || '').toString().toUpperCase().replace(/[^A-Z_]/g, '')
  const severity      = (body.severity  || 'INFO').toString().toUpperCase()
  const reason        = (body.reason    || '').toString().slice(0, 512)
  const loaderVersion = (body.loaderVersion || '').toString().slice(0, 20)
  const fingerprint   = (body.fingerprint   || '').toString().slice(0, 64)
  const revoke        = body.revoke === true

  // Validate event type against allowlist.
  if (!ALLOWED_EVENTS.has(eventType)) {
    res.status(400).json({ error: 'Unknown event type' })
    return
  }

  // Validate severity.
  if (!(severity in SEVERITY_RANK)) {
    res.status(400).json({ error: 'Invalid severity' })
    return
  }

  // Find the active license for this user/session.
  const session = await prisma.session.findFirst({
    where: { userId: user.sub, isRevoked: false },
    include: { license: { include: { holder: { select: { username: true } } } } },
    orderBy: { createdAt: 'desc' },
  })

  const licenseId     = session?.licenseId ?? undefined
  const licensePrefix = session?.license?.keyPrefix ?? '—'

  // Log the security event (append-only).
  await prisma.securityEvent.create({
    data: {
      type:      eventType,
      userId:    user.sub,
      licenseId,
      metadata:  JSON.stringify({ severity, reason, loaderVersion, fingerprint, revoke }),
      ipHash:    hashIp(req.ip ?? ''),
    },
  })

  logger.warn('Security event received', {
    eventType, severity, userId: user.sub,
    licenseId, reason, loaderVersion, revoke,
  })

  // If revoke = true OR CRITICAL → mark license COMPROMISED + revoke all sessions.
  const shouldRevoke = revoke || SEVERITY_RANK[severity] >= SEVERITY_RANK['CRITICAL']

  if (shouldRevoke && licenseId) {
    // Mark license as COMPROMISED (irreversible).
    await prisma.$executeRaw`
      UPDATE "License"
      SET status = 'COMPROMISED',
          "updatedAt" = NOW()
      WHERE id = ${licenseId}
    `

    // Revoke all active sessions for this user.
    await prisma.session.updateMany({
      where: { userId: user.sub, isRevoked: false },
      data:  { isRevoked: true, revokedAt: new Date(), revokedReason: eventType },
    })

    // Revoke all refresh tokens.
    await prisma.refreshToken.updateMany({
      where: { userId: user.sub, revokedAt: null },
      data:  { revokedAt: new Date() },
    })

    logger.error('License COMPROMISED — all sessions revoked', {
      userId: user.sub, licenseId, eventType, reason,
    })
  }

  // Suspend (not COMPROMISED) on HIGH events without revoke flag.
  const shouldSuspend = !shouldRevoke && SEVERITY_RANK[severity] >= SEVERITY_RANK['HIGH'] && licenseId
  if (shouldSuspend) {
    await prisma.$executeRaw`
      UPDATE "License"
      SET status = 'SUSPENDED',
          "updatedAt" = NOW()
      WHERE id = ${licenseId}
        AND status = 'ACTIVE'
    `
  }

  // Send Discord alert for HIGH and CRITICAL.
  if (SEVERITY_RANK[severity] >= SEVERITY_RANK['HIGH']) {
    sendDiscordAlert(
      { eventType, severity, reason, loaderVersion, fingerprint, revoke },
      licensePrefix,
      user.sub
    ).catch(() => {})
  }

  res.json({
    received:    true,
    action:      shouldRevoke ? 'REVOKED' : shouldSuspend ? 'SUSPENDED' : 'LOGGED',
    authorized:  !shouldRevoke,
    status:      shouldRevoke ? 'COMPROMISED' : 'OK',
  })
}

// GET /api/security/events — admin listing with pagination and filters.
export async function handleListEvents(req: Request, res: Response) {
  const page     = Math.max(1, parseInt(req.query.page as string) || 1)
  const limit    = Math.min(100, parseInt(req.query.limit as string) || 25)
  const severity = req.query.severity as string | undefined
  const type     = req.query.type as string | undefined
  const userId   = req.query.userId as string | undefined

  const metaFilter: string[] = []
  if (severity) metaFilter.push(`"severity":"${severity}"`)
  if (type)     { /* handled by `type` field below */ }

  const where: Record<string, unknown> = {}
  if (type)   where.type   = type.toUpperCase()
  if (userId) where.userId = userId

  const [events, total] = await Promise.all([
    prisma.securityEvent.findMany({
      where,
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: { user: { select: { username: true } }, license: { select: { keyPrefix: true } } },
    }),
    prisma.securityEvent.count({ where }),
  ])

  res.json({ events, total, page, limit })
}

// ──────────────────── util ────────────────────

import crypto from 'crypto'

function hashIp(ip: string): string {
  return crypto.createHash('sha256').update(ip + (process.env.IP_HASH_SALT ?? 'isl')).digest('hex').slice(0, 32)
}
