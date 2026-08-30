import { Request, Response } from 'express'
import { z } from 'zod'
import { loginWithCredentials, loginWithLicense } from '../services/authService'
import {
  getSessionStatus,
  validateRequestTimestamp,
  consumeNonce,
  rotateRefreshToken,
  revokeSession,
  revokeAccessJti,
} from '../services/tokenService'
import { audit } from '../services/auditService'
import { notifyWebhook } from '../services/webhookService'
import { AppError, Errors } from '../utils/errors'
import { AuthenticatedRequest } from '../types'
import { prisma } from '../db'
import { config } from '../config'

const hardwareInfoSchema = z.object({
  cpuId: z.string().max(128).optional(),
  motherboardSerial: z.string().max(128).optional(),
  diskSerial: z.string().max(128).optional(),
  biosSerial: z.string().max(128).optional(),
  macAddress: z.string().max(64).optional(),
  systemUuid: z.string().max(128).optional(),
  processorName: z.string().max(256).optional(),
  totalMemory: z.number().optional(),
  screenResolution: z.string().max(32).optional(),
  timezone: z.string().max(64).optional(),
}).partial().optional()

const credSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256),
  fingerprint: z.string().length(64),
  nonce: z.string().uuid(),
  timestamp: z.number().int(),
  hardwareInfo: hardwareInfoSchema,
})

const licSchema = z.object({
  licenseKey: z.string().regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i),
  fingerprint: z.string().length(64),
  nonce: z.string().uuid(),
  timestamp: z.number().int(),
  hardwareInfo: hardwareInfoSchema,
})

const heartbeatSchema = z.object({
  sessionCheck: z.boolean().optional(),
  fingerprint: z.string().length(64).optional(),
  debugScore: z.number().int().min(0).max(100).optional(),
  vmScore: z.number().int().min(0).max(100).optional(),
  tamperScore: z.number().int().min(0).max(100).optional(),
})

const attestSchema = z.object({
  nonce: z.string().uuid(),
  timestamp: z.number().int(),
  fingerprint: z.string().length(64),
  integrityOk: z.boolean(),
  debugScore: z.number().int().min(0).max(100),
  vmScore: z.number().int().min(0).max(100),
  tamperScore: z.number().int().min(0).max(100),
  signedPe: z.boolean().optional(),
})

const threatSchema = z.object({
  source: z.string().max(64),
  detail: z.string().max(512).optional(),
  severity: z.number().int().min(0).max(10),
})

function ip(req: Request) {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || ''
}

export async function handleCredentialLogin(req: Request, res: Response) {
  const parsed = credSchema.safeParse(req.body)
  if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }
  try {
    const result = await loginWithCredentials({ ...parsed.data, ip: ip(req), hardwareInfo: parsed.data.hardwareInfo as never })
    res.json(result)
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message, code: e.code })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleLicenseLogin(req: Request, res: Response) {
  const parsed = licSchema.safeParse(req.body)
  if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }
  try {
    const result = await loginWithLicense({ ...parsed.data, ip: ip(req), hardwareInfo: parsed.data.hardwareInfo as never })
    res.json(result)
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message, code: e.code })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleRefresh(req: Request, res: Response) {
  const { refreshToken } = req.body
  if (!refreshToken || typeof refreshToken !== 'string') { res.status(400).json({ error: 'Missing refreshToken' }); return }
  try {
    res.json(await rotateRefreshToken(refreshToken))
  } catch {
    res.status(401).json({ error: 'Invalid refresh token' })
  }
}

export async function handleLogout(req: Request, res: Response) {
  const user = (req as AuthenticatedRequest).user
  await revokeAccessJti(user.jti)
  await revokeSession(user.sessionId)
  res.json({ success: true })
}

export async function handleMe(req: Request, res: Response) {
  const user = (req as AuthenticatedRequest).user
  const st = await getSessionStatus(user.sessionId)
  if (st.revoked) {
    res.status(401).json({ error: 'Session revoked', status: 'REVOKED' })
    return
  }
  res.json({ userId: user.sub, role: user.role, sessionId: user.sessionId, status: st.status })
}

export async function handleHeartbeat(req: Request, res: Response) {
  const user = (req as AuthenticatedRequest).user
  const parsed = heartbeatSchema.safeParse(req.body ?? {})
  if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }

  const st = await getSessionStatus(user.sessionId)
  if (st.revoked) {
    res.status(401).json({ error: 'Session revoked', status: 'REVOKED' })
    return
  }

  await prisma.session.updateMany({
    where: { id: user.sessionId },
    data: {
      lastSeenAt: new Date(),
      riskScore: Math.max(
        parsed.data.debugScore ?? 0,
        parsed.data.vmScore ?? 0,
        parsed.data.tamperScore ?? 0,
      ),
    },
  })

  // High client threat scores → soft revoke recommendation
  const threat =
    (parsed.data.debugScore ?? 0) >= 18 ||
    (parsed.data.tamperScore ?? 0) >= 10
  if (threat) {
    await audit({
      eventType: 'HEARTBEAT',
      result: 'WARNING',
      userId: user.sub,
      metadata: parsed.data,
    })
    res.status(403).json({ status: 'REVOKED', error: 'Client integrity failure' })
    return
  }

  res.json({ status: 'ACTIVE', serverTime: Math.floor(Date.now() / 1000) })
}

export async function handleAttest(req: Request, res: Response) {
  try {
    const user = (req as AuthenticatedRequest).user
    const parsed = attestSchema.safeParse(req.body)
    if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }

    if (!validateRequestTimestamp(parsed.data.timestamp, config.ATTEST_MAX_AGE_SEC)) {
      res.status(400).json({ error: 'Replay detected' })
      return
    }
    if (!(await consumeNonce(parsed.data.nonce))) {
      res.status(400).json({ error: 'Replay detected' })
      return
    }

    const st = await getSessionStatus(user.sessionId)
    if (st.revoked) {
      res.status(401).json({ status: 'REVOKED', error: 'Session revoked' })
      return
    }

    const fail =
      !parsed.data.integrityOk ||
      parsed.data.debugScore >= 18 ||
      parsed.data.tamperScore >= 10

    await audit({
      eventType: 'ATTEST',
      result: fail ? 'FAILURE' : 'SUCCESS',
      userId: user.sub,
      metadata: parsed.data,
    })

    if (fail) {
      await prisma.session.updateMany({
        where: { id: user.sessionId },
        data: { isRevoked: true, revokedAt: new Date(), revokedReason: 'attest_failed' },
      })
      res.status(403).json({ status: 'REVOKED', error: 'Attestation failed' })
      return
    }

    await prisma.session.updateMany({
      where: { id: user.sessionId },
      data: {
        lastSeenAt: new Date(),
        hardwareVerified: true,
        hardwareVerifiedAt: new Date(),
        deviceFingerprint: parsed.data.fingerprint,
      },
    })

    res.json({ status: 'ACTIVE', attested: true, serverTime: Math.floor(Date.now() / 1000) })
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleClientThreat(req: Request, res: Response) {
  const user = (req as AuthenticatedRequest).user
  const parsed = threatSchema.safeParse(req.body)
  if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }

  await audit({
    eventType: 'CLIENT_THREAT',
    result: parsed.data.severity >= 7 ? 'FAILURE' : 'WARNING',
    userId: user.sub,
    metadata: parsed.data,
  })

  if (parsed.data.severity >= 7) {
    await notifyWebhook({
      title: 'Immortal threat',
      body: `${parsed.data.source}: ${parsed.data.detail || 'n/a'}`,
      severity: parsed.data.severity,
      userId: user.sub,
    })
  }

  if (parsed.data.severity >= 9) {
    await prisma.session.updateMany({
      where: { id: user.sessionId },
      data: { isRevoked: true, revokedAt: new Date(), revokedReason: parsed.data.source },
    })
    res.json({ status: 'REVOKED' })
    return
  }
  res.json({ status: 'LOGGED' })
}
