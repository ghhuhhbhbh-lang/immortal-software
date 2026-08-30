import rateLimit from 'express-rate-limit'
import { config } from '../config'

export const loginLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_LOGIN_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'Too many login attempts. Please wait a minute and try again.' },
})

export const apiLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_API_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'You are sending requests too quickly. Slow down a bit.' },
})

export const activateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: config.RATE_LIMIT_ACTIVATE_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Activation limit reached for this hour. Try again later.' },
})
