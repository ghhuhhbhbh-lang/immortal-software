import { prisma } from '../db'
import { config } from '../config'
import { hashPassword, verifyPassword, hashToken, hashIp } from '../utils/crypto'
import { generateAccessToken, generateRefreshToken, consumeNonce, validateRequestTimestamp } from './tokenService'
import { findLicenseByKey, validateLicenseStatus } from './licenseService'
import { resolveDevice } from './deviceService'
import { audit } from './auditService'
import { Errors } from '../utils/errors'
import { TokenPair } from '../types'

interface LoginWithCredentials {
  username: string
  password: string
  fingerprint: string
  nonce: string
  timestamp: number
  ip?: string
}

interface LoginWithLicense {
  licenseKey: string
  fingerprint: string
  nonce: string
  timestamp: number
  ip?: string
}

export async function loginWithCredentials(params: LoginWithCredentials): Promise<TokenPair & { username: string; role: string }> {
  const { username, password, fingerprint, nonce, timestamp, ip } = params
  const ipHash = ip ? hashIp(ip) : undefined

  if (!validateRequestTimestamp(timestamp)) {
    await audit({ eventType: 'REPLAY_DETECTED', result: 'FAILURE', ipHash })
    throw Errors.REPLAY_DETECTED()
  }
  if (!await consumeNonce(nonce)) {
    await audit({ eventType: 'REPLAY_DETECTED', result: 'FAILURE', ipHash })
    throw Errors.REPLAY_DETECTED()
  }

  const user = await prisma.user.findFirst({ where: { OR: [{ username }, { email: username }] } })
  if (!user || !await verifyPassword(user.passwordHash, password)) {
    await audit({ eventType: 'LOGIN_FAILURE', result: 'FAILURE', userId: user?.id, ipHash })
    throw Errors.INVALID_CREDS()
  }
  if (user.status !== 'ACTIVE') {
    await audit({ eventType: 'LOGIN_FAILURE', result: 'FAILURE', userId: user.id, ipHash })
    throw Errors.ACCOUNT_SUSPENDED()
  }

  const expiresAt = new Date(Date.now() + config.SESSION_ABSOLUTE_LIFETIME_DAYS * 86_400_000)
  const rawRefresh = generateRefreshToken()
  const session = await prisma.session.create({
    data: { userId: user.id, refreshTokenHash: hashToken(rawRefresh), ipHash, expiresAt, lastActivityAt: new Date() },
  })

  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } })
  await audit({ eventType: 'LOGIN_SUCCESS', result: 'SUCCESS', userId: user.id, ipHash })

  const accessToken = generateAccessToken({ sub: user.id, role: user.role, sessionId: session.id })
  return { accessToken, refreshToken: rawRefresh, sessionId: session.id, username: user.username, role: user.role }
}

export async function loginWithLicense(params: LoginWithLicense): Promise<TokenPair & { username: string; expiry: string; products: string[] }> {
  const { licenseKey, fingerprint, nonce, timestamp, ip } = params
  const ipHash = ip ? hashIp(ip) : undefined

  if (!validateRequestTimestamp(timestamp)) {
    await audit({ eventType: 'REPLAY_DETECTED', result: 'FAILURE', ipHash })
    throw Errors.REPLAY_DETECTED()
  }
  if (!await consumeNonce(nonce)) {
    await audit({ eventType: 'REPLAY_DETECTED', result: 'FAILURE', ipHash })
    throw Errors.REPLAY_DETECTED()
  }

  const license = await findLicenseByKey(licenseKey)
  if (!license) {
    await audit({ eventType: 'LOGIN_FAILURE', result: 'FAILURE', ipHash })
    throw Errors.LICENSE_INVALID()
  }

  await validateLicenseStatus(license)

  const deviceId = await resolveDevice(license.id, fingerprint, license.deviceLimit)

  if (license.status === 'UNUSED') {
    await prisma.license.update({ where: { id: license.id }, data: { status: 'ACTIVE', activatedAt: new Date() } })
  }

  const expiresAt = new Date(Date.now() + config.SESSION_ABSOLUTE_LIFETIME_DAYS * 86_400_000)
  const rawRefresh = generateRefreshToken()
  const session = await prisma.session.create({
    data: { licenseId: license.id, refreshTokenHash: hashToken(rawRefresh), deviceId, ipHash, expiresAt },
  })

  await audit({ eventType: 'LICENSE_ACTIVATED', result: 'SUCCESS', licenseId: license.id, ipHash })

  const accessToken = generateAccessToken({ sub: license.id, role: 'USER', sessionId: session.id })
  const expiry = license.expirationDate ? license.expirationDate.toLocaleDateString() : 'Lifetime'
  return {
    accessToken, refreshToken: rawRefresh, sessionId: session.id,
    username: license.keyPrefix + '-****', expiry,
    products: [license.product.name],
  }
}

export async function refreshTokens(rawRefreshToken: string): Promise<TokenPair> {
  const hash = hashToken(rawRefreshToken)
  const session = await prisma.session.findUnique({ where: { refreshTokenHash: hash } })
  if (!session || session.isRevoked || session.expiresAt < new Date()) throw Errors.UNAUTHORIZED()

  await prisma.session.update({ where: { id: session.id }, data: { isRevoked: true } })

  const newRefresh = generateRefreshToken()
  const expiresAt = new Date(Date.now() + config.SESSION_ABSOLUTE_LIFETIME_DAYS * 86_400_000)
  const newSession = await prisma.session.create({
    data: {
      userId: session.userId, licenseId: session.licenseId,
      refreshTokenHash: hashToken(newRefresh),
      deviceId: session.deviceId, ipHash: session.ipHash, expiresAt,
    },
  })

  const sub = session.userId ?? session.licenseId ?? ''
  const accessToken = generateAccessToken({ sub, role: session.userId ? 'USER' : 'USER', sessionId: newSession.id })
  return { accessToken, refreshToken: newRefresh, sessionId: newSession.id }
}

export async function logout(sessionId: string, jti: string, jwtExp: number): Promise<void> {
  await prisma.session.update({ where: { id: sessionId }, data: { isRevoked: true } }).catch(() => {})
  await prisma.revokedToken.upsert({
    where: { jti }, update: {},
    create: { jti, expiresAt: new Date(jwtExp * 1000) },
  })
}
