import { Request, Response } from 'express'
import { z } from 'zod'
import { createLicenses, suspendLicense, revokeLicense, extendLicense } from '../services/licenseService'
import { resetDevices } from '../services/deviceService'
import { audit } from '../services/auditService'
import { prisma } from '../db'
import { AppError, Errors } from '../utils/errors'
import { AuthenticatedRequest } from '../types'

const createSchema = z.object({
  productId: z.string().uuid(),
  planId: z.string().min(1),
  quantity: z.number().int().min(1).max(500).default(1),
  durationDays: z.number().int().min(1).optional().nullable(),
  deviceLimit: z.number().int().min(1).max(50).optional(),
  notes: z.string().max(500).optional(),
})

export async function handleCreateLicenses(req: Request, res: Response) {
  const parsed = createSchema.safeParse(req.body)
  if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }
  try {
    const licenses = await createLicenses(parsed.data)
    const actor = (req as AuthenticatedRequest).user
    await audit({ eventType: 'ADMIN_ACTION', result: 'SUCCESS', userId: actor.sub, metadata: { action: 'create_licenses', count: licenses.length } })
    res.status(201).json({ created: licenses.length, licenses })
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleListLicenses(req: Request, res: Response) {
  const page = Math.max(1, parseInt(req.query.page as string) || 1)
  const limit = Math.min(100, parseInt(req.query.limit as string) || 25)
  const status = req.query.status as string | undefined

  const where = status ? { status: status as never } : {}
  const [licenses, total] = await Promise.all([
    prisma.license.findMany({
      where, skip: (page - 1) * limit, take: limit,
      include: { product: true, plan: true },
      orderBy: { createdAt: 'desc' },
    }),
    prisma.license.count({ where }),
  ])
  res.json({ licenses: licenses.map(l => ({
    id: l.id, keyPrefix: l.keyPrefix, status: l.status,
    product: l.product.name, plan: l.plan.name,
    expirationDate: l.expirationDate, notes: l.notes,
  })), total, page, limit })
}

export async function handleSuspend(req: Request, res: Response) {
  try {
    await suspendLicense(req.params.id)
    const actor = (req as AuthenticatedRequest).user
    await audit({ eventType: 'LICENSE_SUSPENDED', result: 'SUCCESS', userId: actor.sub, licenseId: req.params.id })
    res.json({ success: true })
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleRevoke(req: Request, res: Response) {
  try {
    await revokeLicense(req.params.id)
    const actor = (req as AuthenticatedRequest).user
    await audit({ eventType: 'LICENSE_REVOKED', result: 'SUCCESS', userId: actor.sub, licenseId: req.params.id })
    res.json({ success: true })
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleExtend(req: Request, res: Response) {
  const { days } = req.body
  if (!days || typeof days !== 'number') { res.status(422).json({ error: 'days required' }); return }
  try {
    await extendLicense(req.params.id, days)
    res.json({ success: true })
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleResetDevices(req: Request, res: Response) {
  try {
    await resetDevices(req.params.id)
    const actor = (req as AuthenticatedRequest).user
    await audit({ eventType: 'DEVICE_RESET', result: 'SUCCESS', userId: actor.sub, licenseId: req.params.id })
    res.json({ success: true })
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}
