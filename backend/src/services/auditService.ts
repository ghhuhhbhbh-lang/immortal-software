import { prisma } from '../db'
import { hashIp } from '../utils/crypto'
import type { EventType } from '../types'

export async function logEvent(opts: {
  type: string
  userId?: string
  licenseId?: string
  ip?: string
  userAgent?: string
  metadata?: Record<string, unknown>
}): Promise<void> {
  await prisma.securityEvent.create({
    data: {
      type: opts.type,
      userId: opts.userId,
      licenseId: opts.licenseId,
      ipHash: opts.ip ? hashIp(opts.ip) : undefined,
      userAgent: opts.userAgent?.slice(0, 512),
      metadata: opts.metadata ? JSON.stringify(opts.metadata) : undefined,
    },
  }).catch(() => {})
}

/** Compatible alias used by authService */
export async function audit(opts: {
  eventType: string
  result: string
  userId?: string
  licenseId?: string
  ipHash?: string
  metadata?: Record<string, unknown>
}): Promise<void> {
  await prisma.securityEvent.create({
    data: {
      type: opts.eventType,
      userId: opts.userId,
      licenseId: opts.licenseId,
      ipHash: opts.ipHash,
      metadata: JSON.stringify({ result: opts.result, ...(opts.metadata || {}) }),
    },
  }).catch(() => {})
}

export type { EventType }
