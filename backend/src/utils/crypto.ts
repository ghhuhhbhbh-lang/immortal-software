import crypto from 'crypto'
import argon2 from 'argon2'

const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

export function generateLicenseKey(): string {
  const bytes = crypto.randomBytes(20)
  let raw = ''
  for (let i = 0; i < 20; i++) raw += CHARSET[bytes[i] % CHARSET.length]
  return `${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}-${raw.slice(12,16)}-${raw.slice(16,20)}`
}

const ARGON_OPTS = { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 } as const

export const hashPassword    = (p: string) => argon2.hash(p, ARGON_OPTS)
export const verifyPassword  = (hash: string, p: string) => argon2.verify(hash, p)
export const hashLicenseKey  = (key: string) => argon2.hash(key.replace(/-/g,'').toUpperCase(), ARGON_OPTS)
export const verifyLicenseKey = (hash: string, key: string) => argon2.verify(hash, key.replace(/-/g,'').toUpperCase())

export const sha256    = (s: string) => crypto.createHash('sha256').update(s).digest('hex')
export const hashIp    = (ip: string) => sha256(ip + 'immortal-ip-salt-v1')
export const hashToken = (t: string) => sha256(t)
export const randomHex = (bytes = 48) => crypto.randomBytes(bytes).toString('hex')

export function validateRequestTimestamp(ts: number, windowSec = 300): boolean {
  return Math.abs(Math.floor(Date.now() / 1000) - ts) <= windowSec
}

export function hammingSimilarity(a: string, b: string): number {
  if (a.length !== b.length) return 0
  let same = 0
  for (let i = 0; i < a.length; i++) if (a[i] === b[i]) same++
  return same / a.length
}
