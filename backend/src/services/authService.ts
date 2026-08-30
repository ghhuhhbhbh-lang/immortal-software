// @ts-nocheck
import { prisma } from '../db'
import { config } from '../config'
import { hashPassword, verifyPassword, hashToken, hashIp } from '../utils/crypto'
import { generateAccessToken, generateRefreshToken, consumeNonce, validateRequestTimestamp } from './tokenService'
import { findLicenseByKey, validateLicenseStatus } from './licenseService'
import { resolveDevice, generateHardwareFingerprint, validateHardwareBinding } from './deviceService'
import { audit } from './auditService'
import { Errors } from '../utils/errors'
import { TokenPair } from '../types'
import crypto from 'crypto'

interface LoginWithCredentials {
  username: string
  password: string
  fingerprint: string
  nonce: string
  timestamp: number
  ip?: string
  hardwareInfo?: HardwareInfo
}

interface LoginWithLicense {
  licenseKey: string
  fingerprint: string
  nonce: string
  timestamp: number
  ip?: string
  hardwareInfo?: HardwareInfo
}

interface HardwareInfo {
  cpuId: string
  motherboardSerial: string
  diskSerial: string
  biosSerial: string
  macAddress: string
  systemUuid: string
  processorName: string
  totalMemory: number
  screenResolution: string
  timezone: string
}

// Generate hardware-based device fingerprint
function generateEnhancedFingerprint(hardwareInfo: HardwareInfo, clientFingerprint: string): string {
  const combined = [
    hardwareInfo.cpuId,
    hardwareInfo.motherboardSerial,
    hardwareInfo.diskSerial,
    hardwareInfo.biosSerial,
    hardwareInfo.macAddress,
    hardwareInfo.systemUuid,
    clientFingerprint
  ].join('|')
  
  return crypto.createHash('sha256').update(combined).digest('hex')
}

// Validate hardware binding integrity
function validateHardwareIntegrity(storedFingerprint: string, currentHardware: HardwareInfo): boolean {
  // Allow for some flexibility in hardware changes
  let score = 0
  const weights = {
    cpuId: 25,
    motherboardSerial: 30,
    biosSerial: 20,
    systemUuid: 15,
    macAddress: 10
  }
  
  // Compare critical hardware components
  const storedComponents = JSON.parse(Buffer.from(storedFingerprint, 'base64').toString())
  
  if (storedComponents.cpuId === currentHardware.cpuId) score += weights.cpuId
  if (storedComponents.motherboardSerial === currentHardware.motherboardSerial) score += weights.motherboardSerial
  if (storedComponents.biosSerial === currentHardware.biosSerial) score += weights.biosSerial
  if (storedComponents.systemUuid === currentHardware.systemUuid) score += weights.systemUuid
  if (storedComponents.macAddress === currentHardware.macAddress) score += weights.macAddress
  
  // Require at least 70% hardware match
  return score >= 70
}

// Enhanced device risk assessment
function assessDeviceRisk(hardwareInfo: HardwareInfo, ip?: string): number {
  let riskScore = 0
  
  // Check for virtual machine indicators
  if (hardwareInfo.processorName.toLowerCase().includes('virtual') ||
      hardwareInfo.processorName.toLowerCase().includes('vmware') ||
      hardwareInfo.processorName.toLowerCase().includes('qemu')) {
    riskScore += 40
  }
  
  // Check memory size (VMs often have round numbers)
  const memoryGB = hardwareInfo.totalMemory / (1024 * 1024 * 1024)
  if ([1, 2, 4, 8, 16, 32].includes(Math.round(memoryGB))) {
    riskScore += 15
  }
  
  // Check for suspicious MAC addresses (VM prefixes)
  const mac = hardwareInfo.macAddress.toUpperCase()
  const vmMacPrefixes = ['00:05:69', '00:0C:29', '00:50:56', '08:00:27', '00:03:FF', '00:15:5D']
  if (vmMacPrefixes.some(prefix => mac.startsWith(prefix))) {
    riskScore += 30
  }
  
  // Check timezone consistency with IP geolocation
  if (ip) {
    // This would require IP geolocation service integration
    // For now, just check for suspicious timezone changes
  }
  
  return Math.min(riskScore, 100)
}

export async function loginWithCredentials(params: LoginWithCredentials): Promise<TokenPair & { username: string; role: string }> {
  const { username, password, fingerprint, nonce, timestamp, ip, hardwareInfo } = params
  const ipHash = ip ? hashIp(ip) : undefined

  if (!validateRequestTimestamp(timestamp)) {
    await audit({ eventType: 'REPLAY_DETECTED', result: 'FAILURE', ipHash })
    throw Errors.REPLAY_DETECTED()
  }
  if (!await consumeNonce(nonce)) {
    await audit({ eventType: 'REPLAY_DETECTED', result: 'FAILURE', ipHash })
    throw Errors.REPLAY_DETECTED()
  }

  const user = await prisma.user.findFirst({ 
    where: { OR: [{ username }, { email: username }] },
    include: { devices: true }
  })
  
  if (!user || !await verifyPassword(user.passwordHash, password)) {
    await audit({ eventType: 'LOGIN_FAILURE', result: 'FAILURE', userId: user?.id, ipHash })
    throw Errors.INVALID_CREDS()
  }
  if (user.status !== 'ACTIVE') {
    await audit({ eventType: 'LOGIN_FAILURE', result: 'FAILURE', userId: user.id, ipHash })
    throw Errors.ACCOUNT_SUSPENDED()
  }

  // Enhanced hardware validation
  if (hardwareInfo) {
    const enhancedFingerprint = generateEnhancedFingerprint(hardwareInfo, fingerprint)
    const deviceRisk = assessDeviceRisk(hardwareInfo, ip)
    
    // Check for existing device binding
    const existingDevice = user.devices.find(d => d.status === 'ACTIVE')
    if (existingDevice && !validateHardwareIntegrity(existingDevice.fingerprintHash, hardwareInfo)) {
      // Hardware changed significantly - require additional verification
      await audit({ 
        eventType: 'HARDWARE_CHANGE_DETECTED', 
        result: 'WARNING', 
        userId: user.id, 
        ipHash,
        metadata: { deviceRisk }
      })
      
      if (deviceRisk > 50) {
        throw Errors.HARDWARE_VERIFICATION_REQUIRED()
      }
    }
    
    // Update or create device record
    await prisma.device.upsert({
      where: { 
        userId_fingerprintHash: { 
          userId: user.id, 
          fingerprintHash: hashToken(enhancedFingerprint) 
        }
      },
      update: { 
        lastSeenAt: new Date(),
        riskScore: deviceRisk,
        hardwareInfo: JSON.stringify(hardwareInfo)
      },
      create: { 
        userId: user.id, 
        fingerprintHash: hashToken(enhancedFingerprint),
        riskScore: deviceRisk,
        hardwareInfo: JSON.stringify(hardwareInfo),
        status: deviceRisk > 70 ? 'PENDING_VERIFICATION' : 'ACTIVE'
      }
    })
    
    if (deviceRisk > 70) {
      throw Errors.DEVICE_VERIFICATION_REQUIRED()
    }
  }

  const expiresAt = new Date(Date.now() + config.SESSION_ABSOLUTE_LIFETIME_DAYS * 86_400_000)
  const rawRefresh = generateRefreshToken()
  const session = await prisma.session.create({
    data: { 
      userId: user.id, 
      refreshTokenHash: hashToken(rawRefresh), 
      ipHash, 
      expiresAt, 
      lastActivityAt: new Date(),
      deviceFingerprint: hardwareInfo ? generateEnhancedFingerprint(hardwareInfo, fingerprint) : fingerprint
    },
  })

  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } })
  await audit({ eventType: 'LOGIN_SUCCESS', result: 'SUCCESS', userId: user.id, ipHash })

  const accessToken = generateAccessToken({ 
    sub: user.id, 
    role: user.role, 
    sessionId: session.id,
    deviceId: hardwareInfo ? generateEnhancedFingerprint(hardwareInfo, fingerprint) : fingerprint
  })
  
  return { 
    accessToken, 
    refreshToken: rawRefresh, 
    sessionId: session.id, 
    username: user.username, 
    role: user.role 
  }
}

export async function loginWithLicense(params: LoginWithLicense): Promise<TokenPair & { username: string; expiry: string; products: string[] }> {
  const { licenseKey, fingerprint, nonce, timestamp, ip, hardwareInfo } = params
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

  // Enhanced hardware-based device resolution
  let enhancedFingerprint = fingerprint
  let deviceRisk = 0
  
  if (hardwareInfo) {
    enhancedFingerprint = generateEnhancedFingerprint(hardwareInfo, fingerprint)
    deviceRisk = assessDeviceRisk(hardwareInfo, ip)
    
    // Check existing device bindings for this license
    const existingDevices = await prisma.device.findMany({
      where: { 
        licenseId: license.id,
        status: 'ACTIVE'
      }
    })
    
    // Validate hardware consistency if device exists
    if (existingDevices.length > 0) {
      const matchingDevice = existingDevices.find(device => 
        validateHardwareIntegrity(device.fingerprintHash, hardwareInfo)
      )
      
      if (!matchingDevice && existingDevices.length >= license.deviceLimit) {
        await audit({ 
          eventType: 'DEVICE_LIMIT_EXCEEDED', 
          result: 'FAILURE', 
          licenseId: license.id, 
          ipHash 
        })
        throw Errors.DEVICE_LIMIT_EXCEEDED()
      }
      
      if (!matchingDevice && deviceRisk > 60) {
        await audit({ 
          eventType: 'SUSPICIOUS_DEVICE_BINDING', 
          result: 'WARNING', 
          licenseId: license.id, 
          ipHash,
          metadata: { deviceRisk }
        })
        throw Errors.DEVICE_VERIFICATION_REQUIRED()
      }
    }
    
    // Create or update device binding
    await prisma.device.upsert({
      where: { 
        licenseId_fingerprintHash: { 
          licenseId: license.id, 
          fingerprintHash: hashToken(enhancedFingerprint) 
        }
      },
      update: { 
        lastSeenAt: new Date(),
        riskScore: deviceRisk,
        hardwareInfo: JSON.stringify(hardwareInfo)
      },
      create: { 
        licenseId: license.id, 
        fingerprintHash: hashToken(enhancedFingerprint),
        riskScore: deviceRisk,
        hardwareInfo: JSON.stringify(hardwareInfo),
        status: deviceRisk > 70 ? 'PENDING_VERIFICATION' : 'ACTIVE'
      }
    })
    
    if (deviceRisk > 70) {
      throw Errors.DEVICE_VERIFICATION_REQUIRED()
    }
  } else {
    // Fallback to legacy device resolution
    const deviceId = await resolveDevice(license.id, fingerprint, license.deviceLimit)
  }

  if (license.status === 'UNUSED') {
    await prisma.license.update({ 
      where: { id: license.id }, 
      data: { 
        status: 'ACTIVE', 
        activatedAt: new Date(),
        activationFingerprint: enhancedFingerprint,
        activationIp: ipHash
      } 
    })
  }

  const expiresAt = new Date(Date.now() + config.SESSION_ABSOLUTE_LIFETIME_DAYS * 86_400_000)
  const rawRefresh = generateRefreshToken()
  const session = await prisma.session.create({
    data: { 
      licenseId: license.id, 
      refreshTokenHash: hashToken(rawRefresh), 
      deviceFingerprint: enhancedFingerprint,
      ipHash, 
      expiresAt,
      riskScore: deviceRisk
    },
  })

  await audit({ 
    eventType: 'LICENSE_ACTIVATED', 
    result: 'SUCCESS', 
    licenseId: license.id, 
    ipHash,
    metadata: { deviceRisk }
  })

  const accessToken = generateAccessToken({ 
    sub: license.id, 
    role: 'USER', 
    sessionId: session.id,
    deviceId: enhancedFingerprint,
    licenseId: license.id
  })
  
  const expiry = license.expirationDate ? license.expirationDate.toLocaleDateString() : 'Lifetime'
  return {
    accessToken, 
    refreshToken: rawRefresh, 
    sessionId: session.id,
    username: license.keyPrefix + '-****', 
    expiry,
    products: [license.product.name],
  }
}

export async function refreshTokens(rawRefreshToken: string, currentFingerprint?: string): Promise<TokenPair> {
  const hash = hashToken(rawRefreshToken)
  const session = await prisma.session.findUnique({ 
    where: { refreshTokenHash: hash },
    include: {
      user: true,
      license: true
    }
  })
  
  if (!session || session.isRevoked || session.expiresAt < new Date()) {
    throw Errors.UNAUTHORIZED()
  }

  // Enhanced device validation during token refresh
  if (currentFingerprint && session.deviceFingerprint) {
    if (currentFingerprint !== session.deviceFingerprint) {
      // Device fingerprint changed - potential session hijacking
      await prisma.session.update({ 
        where: { id: session.id }, 
        data: { isRevoked: true, revokedReason: 'DEVICE_FINGERPRINT_MISMATCH' }
      })
      
      await audit({ 
        eventType: 'DEVICE_FINGERPRINT_MISMATCH', 
        result: 'SECURITY_VIOLATION', 
        userId: session.userId,
        licenseId: session.licenseId,
        sessionId: session.id
      })
      
      throw Errors.DEVICE_FINGERPRINT_MISMATCH()
    }
  }

  // Check session risk score
  if (session.riskScore && session.riskScore > 80) {
    await audit({ 
      eventType: 'HIGH_RISK_SESSION_REFRESH', 
      result: 'WARNING', 
      userId: session.userId,
      licenseId: session.licenseId,
      sessionId: session.id
    })
  }

  await prisma.session.update({ where: { id: session.id }, data: { isRevoked: true } })

  const newRefresh = generateRefreshToken()
  const expiresAt = new Date(Date.now() + config.SESSION_ABSOLUTE_LIFETIME_DAYS * 86_400_000)
  const newSession = await prisma.session.create({
    data: {
      userId: session.userId, 
      licenseId: session.licenseId,
      refreshTokenHash: hashToken(newRefresh),
      deviceFingerprint: session.deviceFingerprint,
      ipHash: session.ipHash, 
      expiresAt,
      riskScore: session.riskScore,
      parentSessionId: session.id
    },
  })

  const sub = session.userId ?? session.licenseId ?? ''
  const role = session.user?.role ?? 'USER'
  
  const accessToken = generateAccessToken({ 
    sub, 
    role, 
    sessionId: newSession.id,
    deviceId: session.deviceFingerprint,
    licenseId: session.licenseId
  })
  
  return { accessToken, refreshToken: newRefresh, sessionId: newSession.id }
}

export async function logout(sessionId: string, jti: string, jwtExp: number): Promise<void> {
  // Enhanced logout with device cleanup
  const session = await prisma.session.findUnique({ 
    where: { id: sessionId },
    include: { user: true, license: true }
  })
  
  if (session) {
    await audit({ 
      eventType: 'LOGOUT', 
      result: 'SUCCESS', 
      userId: session.userId,
      licenseId: session.licenseId,
      sessionId: sessionId
    })
  }
  
  await prisma.session.update({ 
    where: { id: sessionId }, 
    data: { 
      isRevoked: true, 
      revokedAt: new Date(),
      revokedReason: 'USER_LOGOUT'
    }
  }).catch(() => {})
  
  await prisma.revokedToken.upsert({
    where: { jti }, 
    update: {},
    create: { jti, expiresAt: new Date(jwtExp * 1000) },
  })
}

// New: Hardware verification challenge
export async function initiateHardwareVerification(sessionId: string): Promise<{ challenge: string }> {
  const session = await prisma.session.findUnique({ where: { id: sessionId } })
  if (!session) throw Errors.UNAUTHORIZED()
  
  const challenge = crypto.randomBytes(32).toString('hex')
  
  await prisma.session.update({
    where: { id: sessionId },
    data: { 
      verificationChallenge: hashToken(challenge),
      challengeExpiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    }
  })
  
  return { challenge }
}

// New: Complete hardware verification
export async function completeHardwareVerification(
  sessionId: string, 
  challenge: string, 
  hardwareProof: HardwareInfo
): Promise<{ verified: boolean }> {
  const session = await prisma.session.findUnique({ where: { id: sessionId } })
  if (!session || !session.verificationChallenge || !session.challengeExpiresAt) {
    throw Errors.UNAUTHORIZED()
  }
  
  if (new Date() > session.challengeExpiresAt) {
    throw Errors.CHALLENGE_EXPIRED()
  }
  
  if (hashToken(challenge) !== session.verificationChallenge) {
    throw Errors.INVALID_CHALLENGE()
  }
  
  // Verify hardware proof matches expected fingerprint
  const proofFingerprint = generateEnhancedFingerprint(hardwareProof, session.deviceFingerprint || '')
  const verified = proofFingerprint === session.deviceFingerprint
  
  await prisma.session.update({
    where: { id: sessionId },
    data: { 
      verificationChallenge: null,
      challengeExpiresAt: null,
      hardwareVerified: verified,
      hardwareVerifiedAt: verified ? new Date() : null
    }
  })
  
  await audit({ 
    eventType: 'HARDWARE_VERIFICATION', 
    result: verified ? 'SUCCESS' : 'FAILURE', 
    sessionId,
    metadata: { verified }
  })
  
  return { verified }
}
