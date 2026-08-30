import { prisma } from '../db'
import { generateLicenseKey, hashLicenseKey, verifyLicenseKey } from '../utils/crypto'
import { AppError } from '../utils/errors'

export async function createLicenses(opts: {
  productId: string
  planId: string
  quantity: number
  durationDays: number
  createdById: string
}): Promise<string[]> {
  const keys: string[] = []
  for (let i = 0; i < opts.quantity; i++) {
    const key = generateLicenseKey()
    const keyHash = await hashLicenseKey(key)
    const keyPrefix = key.slice(0, 4)
    const expiresAt = new Date(Date.now() + opts.durationDays * 86400000)
    await prisma.license.create({
      data: {
        keyHash,
        keyPrefix,
        productId: opts.productId,
        planId: opts.planId,
        expiresAt,
        createdById: opts.createdById,
      },
    })
    keys.push(key)
  }
  return keys
}

export async function findLicenseByKey(rawKey: string) {
  const prefix = rawKey.replace(/-/g, '').slice(0, 4).toUpperCase()
  const candidates = await prisma.license.findMany({
    where: { keyPrefix: prefix },
    include: { product: true, plan: true },
  })
  for (const lic of candidates) {
    if (await verifyLicenseKey(lic.keyHash, rawKey)) return lic
  }
  return null
}

export async function validateLicense(lic: Awaited<ReturnType<typeof findLicenseByKey>>) {
  if (!lic) throw new AppError(403, 'License not found', 'LICENSE_INVALID')
  if (lic.status !== 'ACTIVE') throw new AppError(403, `License ${lic.status.toLowerCase()}`, 'LICENSE_INVALID')
  if (lic.expiresAt && lic.expiresAt < new Date()) throw new AppError(403, 'License expired', 'LICENSE_INVALID')
}
