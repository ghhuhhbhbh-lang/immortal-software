import { Request, Response, NextFunction } from 'express'
import { verifyAccessToken, isAccessTokenRevoked, touchSession } from '../services/tokenService'
import { Errors } from '../utils/errors'
import { AuthenticatedRequest, JwtPayload } from '../types'

const ROLE_RANK: Record<string, number> = {
  USER: 0, PREMIUM: 1, RESELLER: 2, STAFF: 3, ADMIN: 4, OWNER: 5,
}

export function requireAuth(minRole?: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const auth = req.headers.authorization
      if (!auth?.startsWith('Bearer ')) throw Errors.UNAUTHORIZED()
      const token = auth.slice(7)
      const payload = verifyAccessToken(token) as JwtPayload
      if (payload.type !== 'access') throw Errors.UNAUTHORIZED()
      if (await isAccessTokenRevoked(payload.jti)) throw Errors.UNAUTHORIZED()
      if (minRole && (ROLE_RANK[payload.role] ?? -1) < (ROLE_RANK[minRole] ?? 99)) throw Errors.FORBIDDEN()
      ;(req as AuthenticatedRequest).user = payload
      touchSession(payload.sessionId).catch(() => {})
      next()
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'statusCode' in err) {
        res.status((err as { statusCode: number }).statusCode).json({ error: (err as { message: string }).message })
      } else {
        res.status(401).json({ error: 'Unauthorized' })
      }
    }
  }
}

export const requireAdmin = requireAuth('ADMIN')
export const requireOwner = requireAuth('OWNER')
