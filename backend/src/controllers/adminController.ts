// @ts-nocheck
import { Request, Response } from 'express'
import { prisma } from '../db'
import { audit } from '../services/auditService'
import { AppError } from '../utils/errors'
import { AuthenticatedRequest } from '../types'

export async function handleListUsers(req: Request, res: Response) {
  const page = Math.max(1, parseInt(req.query.page as string) || 1)
  const limit = Math.min(100, parseInt(req.query.limit as string) || 20)
  const q = req.query.q as string | undefined
  const where = q ? { OR: [{ username: { contains: q } }, { email: { contains: q } }] } : {}
  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where, skip: (page - 1) * limit, take: limit,
      select: { id: true, username: true, email: true, role: true, status: true, lastLoginAt: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    }),
    prisma.user.count({ where }),
  ])
  res.json({ users, total })
}

export async function handleSuspendUser(req: Request, res: Response) {
  try {
    await prisma.user.update({ where: { id: req.params.id }, data: { status: 'SUSPENDED' } })
    await prisma.session.updateMany({ where: { userId: req.params.id }, data: { isRevoked: true } })
    const actor = (req as AuthenticatedRequest).user
    await audit({ eventType: 'ACCOUNT_SUSPENDED', result: 'SUCCESS', userId: actor.sub, metadata: { targetId: req.params.id } })
    res.json({ success: true })
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleActivateUser(req: Request, res: Response) {
  await prisma.user.update({ where: { id: req.params.id }, data: { status: 'ACTIVE' } })
  res.json({ success: true })
}

export async function handleListEvents(req: Request, res: Response) {
  const page = Math.max(1, parseInt(req.query.page as string) || 1)
  const limit = Math.min(200, parseInt(req.query.limit as string) || 50)
  const eventType = req.query.eventType as string | undefined
  const result    = req.query.result as string | undefined
  const where: Record<string, unknown> = {}
  if (eventType) where.eventType = eventType
  if (result)    where.result = result
  const [events, total] = await Promise.all([
    prisma.securityEvent.findMany({ where, skip: (page - 1) * limit, take: limit, orderBy: { createdAt: 'desc' } }),
    prisma.securityEvent.count({ where }),
  ])
  res.json({ events, total })
}

export async function handleStats(req: Request, res: Response) {
  const oneHourAgo = new Date(Date.now() - 3_600_000)
  const [totalUsers, totalLicenses, activeLicenses, activeSessions, recentFailures] = await Promise.all([
    prisma.user.count(),
    prisma.license.count(),
    prisma.license.count({ where: { status: 'ACTIVE' } }),
    prisma.session.count({ where: { isRevoked: false, expiresAt: { gt: new Date() } } }),
    prisma.securityEvent.count({ where: { result: 'FAILURE', createdAt: { gte: oneHourAgo } } }),
  ])
  res.json({ totalUsers, totalLicenses, activeLicenses, activeSessions, recentFailures })
}

export async function handleListProducts(req: Request, res: Response) {
  const products = await prisma.product.findMany({ include: { plans: true }, orderBy: { createdAt: 'asc' } })
  res.json(products)
}

export async function handleCreateProduct(req: Request, res: Response) {
  const { name, description } = req.body
  if (!name) { res.status(422).json({ error: 'name required' }); return }
  const product = await prisma.product.create({ data: { name, description }, include: { plans: true } })
  res.status(201).json(product)
}

export async function handleCreatePlan(req: Request, res: Response) {
  const { productId, name, deviceLimit, isLifetime, durationDays, permissions } = req.body
  if (!productId || !name) { res.status(422).json({ error: 'productId and name required' }); return }
  const plan = await prisma.plan.create({
    data: { productId, name, deviceLimit: deviceLimit ?? 1, isLifetime: !!isLifetime, durationDays, permissions: permissions ?? [] },
  })
  res.status(201).json(plan)
}
