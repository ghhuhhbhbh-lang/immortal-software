import { prisma } from '../db'
import { generateLicenseKey, hashLicenseKey, verifyLicenseKey } from '../utils/crypto'
import { AppError } from '../utils/errors'

export type CreatedLicense = {
  id: string
  key: string
  keyPrefix: string
  productId: string
  planId: string
  expiresAt: Date | null
}

export async function createLicenses(opts: {
  productId: string
  planId: string
  quantity: number
  durationDays?: number | null
  deviceLimit?: number
  createdById: string
}): Promise<CreatedLicense[]> {
  const product = await prisma.product.findUnique({ where: { id: opts.productId } })
  if (!product || !product.active) throw new AppError(404, 'Product not found')

  const plan = await prisma.plan.findFirst({
    where: { id: opts.planId, productId: opts.productId, active: true },
  })
  if (!plan) throw new AppError(404, 'Plan not found for this product')

  const days = opts.durationDays && opts.durationDays > 0 ? opts.durationDays : plan.durationDays
  const deviceLimit = opts.deviceLimit ?? plan.deviceLimit ?? product.deviceLimit ?? 1
  const created: CreatedLicense[] = []

  for (let i = 0; i < opts.quantity; i++) {
    const key = generateLicenseKey()
    const keyHash = await hashLicenseKey(key)
    const keyPrefix = key.replace(/-/g, '').slice(0, 4).toUpperCase()
    const expiresAt = new Date(Date.now() + days * 86400000)

    const row = await prisma.license.create({
      data: {
        keyHash,
        keyPrefix,
        productId: opts.productId,
        planId: opts.planId,
        expiresAt,
        createdById: opts.createdById,
        deviceLimit,
      },
    })

    created.push({
      id: row.id,
      key,
      keyPrefix: row.keyPrefix,
      productId: row.productId,
      planId: row.planId,
      expiresAt: row.expiresAt,
    })
  }

  return created
}

export async function findLicenseByKey(rawKey: string) {
  const cleaned = rawKey.replace(/-/g, '').toUpperCase()
  const prefix = cleaned.slice(0, 4)
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

export const validateLicenseStatus = validateLicense

export async function suspendLicense(id: string) {
  return prisma.license.update({ where: { id }, data: { status: 'SUSPENDED' } })
}

export async function revokeLicense(id: string) {
  return prisma.license.update({ where: { id }, data: { status: 'REVOKED' } })
}

export async function extendLicense(id: string, extraDays: number) {
  const lic = await prisma.license.findUnique({ where: { id } })
  if (!lic) throw new AppError(404, 'License not found')
  const base = lic.expiresAt && lic.expiresAt > new Date() ? lic.expiresAt : new Date()
  return prisma.license.update({
    where: { id },
    data: { expiresAt: new Date(base.getTime() + extraDays * 86400000), status: 'ACTIVE' },
  })
}
