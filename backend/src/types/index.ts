import { Request } from 'express'

export interface JwtPayload {
  sub: string
  role: string
  sessionId: string
  jti: string
  type: 'access'
  deviceId?: string
  licenseId?: string
  iat?: number
  exp?: number
}

export interface AuthenticatedRequest extends Request {
  user: JwtPayload
}

export interface TokenPair {
  accessToken: string
  refreshToken: string
  sessionId: string
}

export type EventType =
  | 'LOGIN_SUCCESS' | 'LOGIN_FAILURE'
  | 'LOGOUT' | 'TOKEN_REFRESH'
  | 'LICENSE_ACTIVATED' | 'LICENSE_REVOKED' | 'LICENSE_SUSPENDED'
  | 'DEVICE_BOUND' | 'DEVICE_RESET' | 'DEVICE_LIMIT_EXCEEDED'
  | 'SUSPICIOUS_DEVICE_BINDING' | 'REPLAY_DETECTED' | 'RATE_LIMITED'
  | 'ADMIN_ACTION' | 'ACCOUNT_SUSPENDED'
  | 'HEARTBEAT' | 'ATTEST' | 'CLIENT_THREAT'
