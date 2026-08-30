import { z } from 'zod'

const schema = z.object({
  DATABASE_URL:                   z.string().min(1),
  PORT:                           z.coerce.number().default(3000),
  NODE_ENV:                       z.enum(['development','production','test']).default('development'),
  API_BASE_URL:                   z.string().default('http://localhost:3000'),
  JWT_ACCESS_SECRET:              z.string().min(32),
  JWT_REFRESH_SECRET:             z.string().min(32),
  JWT_ACCESS_EXPIRES_IN:          z.string().default('15m'),
  JWT_REFRESH_EXPIRES_DAYS:       z.coerce.number().default(30),
  ALLOWED_ORIGINS:                z.string().default('http://localhost:3000,http://127.0.0.1:3000,null'),
  SEED_ADMIN_USERNAME:            z.string().optional(),
  SEED_ADMIN_EMAIL:               z.string().optional(),
  SEED_ADMIN_PASSWORD:            z.string().optional(),
  RATE_LIMIT_WINDOW_MS:           z.coerce.number().default(60000),
  RATE_LIMIT_LOGIN_MAX:           z.coerce.number().default(5),
  RATE_LIMIT_API_MAX:             z.coerce.number().default(100),
  RATE_LIMIT_ACTIVATE_MAX:        z.coerce.number().default(3),
  SESSION_IDLE_TIMEOUT_HOURS:     z.coerce.number().default(1),
  SESSION_ABSOLUTE_LIFETIME_DAYS: z.coerce.number().default(30),
  NONCE_TTL_SECONDS:              z.coerce.number().default(300),
  ATTEST_MAX_AGE_SEC:             z.coerce.number().default(120),
  REQUIRE_HTTPS_CLIENTS:          z.coerce.boolean().default(false),
  DISCORD_WEBHOOK_URL:            z.string().optional(),
  APP_VERSION:                    z.string().default('2.2.0'),
  OFFLINE_GRACE_HOURS:            z.coerce.number().default(12),
})

const parsed = schema.safeParse(process.env)
if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors)
  process.exit(1)
}

const env = parsed.data

export const config = {
  ...env,
  jwt: {
    accessSecret: env.JWT_ACCESS_SECRET,
    refreshSecret: env.JWT_REFRESH_SECRET,
    accessExpiresIn: env.JWT_ACCESS_EXPIRES_IN,
    refreshExpiresDays: env.JWT_REFRESH_EXPIRES_DAYS,
  },
  ALLOWED_ORIGINS: env.ALLOWED_ORIGINS,
}
