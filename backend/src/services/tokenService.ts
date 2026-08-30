import jwt from 'jsonwebtoken'
import { prisma } from '../db'
import { config } from '../config'
import { hashToken, randomHex } from '../utils/crypto'
import type { JwtPayload, TokenPair } from '../types'

export async function issueTokens(userId: string, role: string, sessionId: string): Promise<TokenPair> {
  const jti = randomHex(16)
  const accessToken = jwt.sign(
    { sub: userId, role, sessionId, jti, type: 'access' } satisfies Omit<JwtPayload, 'iat' | 'exp'>,
    config.jwt.accessSecret,
    { expiresIn: '15m' },
  )

  const rawRefresh = randomHex(48)
  const refreshHash = hashToken(rawRefresh)
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)

  await prisma.refreshToken.create({
    data: { tokenHash: refreshHash, userId, sessionId, expiresAt },
  })

  return { accessToken, refreshToken: rawRefresh, sessionId }
}

export function verifyAccessToken(token: string): JwtPayload {
  return jwt.verify(token, config.jwt.accessSecret) as JwtPayload
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

  return issueTokens(stored.userId, user.role, stored.sessionId)
}

export async function revokeSession(sessionId: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { sessionId, revokedAt: null },
    data: { revokedAt: new Date() },
  })
  await prisma.session.updateMany({
    where: { id: sessionId },
    data: { revokedAt: new Date() },
  })
}
