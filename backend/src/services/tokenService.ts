import jwt from 'jsonwebtoken'
import { prisma } from '../db'
import { config } from '../config'
import { hashToken, randomHex, validateRequestTimestamp as validateTs } from '../utils/crypto'
import type { JwtPayload, TokenPair } from '../types'

const revokedJti = new Set<string>()

export function generateAccessToken(payload: {
  sub: string
  role: string
  sessionId: string
  deviceId?: string
  licenseId?: string
}): string {
  const jti = randomHex(16)
  return jwt.sign(
    {
      sub: payload.sub,
      role: payload.role,
      sessionId: payload.sessionId,
      jti,
      type: 'access' as const,
      ...(payload.deviceId ? { deviceId: payload.deviceId } : {}),
      ...(payload.licenseId ? { licenseId: payload.licenseId } : {}),
    },
    config.jwt.accessSecret,
    { expiresIn: config.jwt.accessExpiresIn as jwt.SignOptions['expiresIn'] },
  )
}

export function generateRefreshToken(): string {
  return randomHex(48)
}

export async function issueTokens(userId: string, role: string, sessionId: string): Promise<TokenPair> {
  const accessToken = generateAccessToken({ sub: userId, role, sessionId })
  const rawRefresh = generateRefreshToken()
  const refreshHash = hashToken(rawRefresh)
  const expiresAt = new Date(Date.now() + config.jwt.refreshExpiresDays * 24 * 60 * 60 * 1000)

  await prisma.refreshToken.create({
    data: { tokenHash: refreshHash, userId, sessionId, expiresAt },
  })

  return { accessToken, refreshToken: rawRefresh, sessionId }
}

export function verifyAccessToken(token: string): JwtPayload {
  return jwt.verify(token, config.jwt.accessSecret) as JwtPayload
}

export async function isAccessTokenRevoked(jti: string): Promise<boolean> {
  return revokedJti.has(jti)
}

export async function revokeAccessJti(jti: string): Promise<void> {
  revokedJti.add(jti)
}

export async function touchSession(sessionId: string): Promise<void> {
  await prisma.session.updateMany({
    where: { id: sessionId, isRevoked: false },
    data: { lastSeenAt: new Date() },
  })
}

export async function rotateRefreshToken(rawRefresh: string): Promise<TokenPair> {
  const hash = hashToken(rawRefresh)
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash: hash } })

  if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
    throw new Error('Invalid or expired refresh token')
  }

  await prisma.refreshToken.update({ where: { tokenHash: hash }, data: { revokedAt: new Date() } })

  const user = await prisma.user.findUnique({ where: { id: stored.userId } })
  if (!user || user.status !== 'ACTIVE') throw new Error('Account inactive')

  const session = await prisma.session.findUnique({ where: { id: stored.sessionId } })
  if (!session || session.isRevoked) throw new Error('Session revoked')

  return issueTokens(stored.userId, user.role, stored.sessionId)
}

export async function revokeSession(sessionId: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { sessionId, revokedAt: null },
    data: { revokedAt: new Date() },
  })
  await prisma.session.updateMany({
    where: { id: sessionId },
    data: { isRevoked: true, revokedAt: new Date(), revokedReason: 'logout_or_server' },
  })
}

/** One-time nonce: insert id, reject duplicates / expired */
export async function consumeNonce(nonce: string): Promise<boolean> {
  if (!nonce || nonce.length < 8 || nonce.length > 128) return false
  const expiresAt = new Date(Date.now() + config.NONCE_TTL_SECONDS * 1000)
  try {
    await prisma.nonce.create({ data: { id: nonce, expiresAt } })
  } catch {
    return false
  }
  // Opportunistic cleanup
  prisma.nonce.deleteMany({ where: { expiresAt: { lt: new Date() } } }).catch(() => {})
  return true
}

export function validateRequestTimestamp(ts: number, windowSec = 300): boolean {
  return validateTs(ts, windowSec)
}

export async function getSessionStatus(sessionId: string): Promise<{
  ok: boolean
  revoked: boolean
  status: string
}> {
  const session = await prisma.session.findUnique({ where: { id: sessionId } })
  if (!session) return { ok: false, revoked: true, status: 'REVOKED' }
  if (session.isRevoked) return { ok: false, revoked: true, status: 'REVOKED' }
  if (session.expiresAt < new Date()) return { ok: false, revoked: true, status: 'EXPIRED' }
  return { ok: true, revoked: false, status: 'ACTIVE' }
}

export async function purgeExpiredRecords(): Promise<void> {
  const now = new Date()
  await prisma.refreshToken.deleteMany({ where: { expiresAt: { lt: now } } })
  await prisma.session.updateMany({
    where: { expiresAt: { lt: now }, isRevoked: false },
    data: { isRevoked: true, revokedAt: now, revokedReason: 'expired' },
  })
}
