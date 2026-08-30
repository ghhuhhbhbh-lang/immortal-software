import { Request, Response } from 'express'
import { z } from 'zod'
import { loginWithCredentials, loginWithLicense, refreshTokens, logout } from '../services/authService'
import { AppError } from '../utils/errors'
import { AuthenticatedRequest } from '../types'

const credSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256),
  fingerprint: z.string().length(64),
  nonce: z.string().uuid(),
  timestamp: z.number().int(),
})

const licSchema = z.object({
  licenseKey: z.string().regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i),
  fingerprint: z.string().length(64),
  nonce: z.string().uuid(),
  timestamp: z.number().int(),
})

function ip(req: Request) {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || ''
}

export async function handleCredentialLogin(req: Request, res: Response) {
  const parsed = credSchema.safeParse(req.body)
  if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }
  try {
    const result = await loginWithCredentials({ ...parsed.data, ip: ip(req) })
    res.json(result)
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleLicenseLogin(req: Request, res: Response) {
  const parsed = licSchema.safeParse(req.body)
  if (!parsed.success) { res.status(422).json({ error: 'Invalid request' }); return }
  try {
    const result = await loginWithLicense({ ...parsed.data, ip: ip(req) })
    res.json(result)
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleRefresh(req: Request, res: Response) {
  const { refreshToken } = req.body
  if (!refreshToken || typeof refreshToken !== 'string') { res.status(400).json({ error: 'Missing refreshToken' }); return }
  try {
    res.json(await refreshTokens(refreshToken))
  } catch (e) {
    if (e instanceof AppError) res.status(e.statusCode).json({ error: e.message })
    else res.status(500).json({ error: 'Internal server error' })
  }
}

export async function handleLogout(req: Request, res: Response) {
  const user = (req as AuthenticatedRequest).user
  await logout(user.sessionId, user.jti, user.exp ?? 0)
  res.json({ success: true })
}

export async function handleMe(req: Request, res: Response) {
  const user = (req as AuthenticatedRequest).user
  res.json({ userId: user.sub, role: user.role, sessionId: user.sessionId })
}
