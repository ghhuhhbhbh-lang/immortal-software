import { prisma } from '../db'
import { hammingSimilarity, sha256 } from '../utils/crypto'
import { AppError } from '../utils/errors'

const MAX_DEVICES = 3
const SIMILARITY_THRESHOLD = 0.85

export async function resolveDevice(userId: string, fingerprint: string): Promise<string> {
  const fpHash = sha256(fingerprint)
  const existing = await prisma.device.findMany({ where: { userId, status: 'ACTIVE' } })

  const match = existing.find(d => hammingSimilarity(d.fingerprintHash, fpHash) >= SIMILARITY_THRESHOLD)
  if (match) {
    await prisma.device.update({
      where: { id: match.id },
      data: { lastSeenAt: new Date(), fingerprintHash: fpHash },
    })
    return match.id
  }

  if (existing.length >= MAX_DEVICES) throw new AppError(403, 'Device limit reached', 'DEVICE_LIMIT')

  const device = await prisma.device.create({ data: { userId, fingerprintHash: fpHash } })
  return device.id
}

export function generateHardwareFingerprint(info: Record<string, unknown>): string {
  return sha256(JSON.stringify(info))
}

export async function validateHardwareBinding(_userId: string, _fingerprint: string): Promise<boolean> {
  return true
}

export async function resetDevices(userId: string) {
  await prisma.device.updateMany({
    where: { userId, status: 'ACTIVE' },
    data: { status: 'REVOKED' },
  })
}
