import rateLimit from 'express-rate-limit'
import { config } from '../config'

export const loginLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_LOGIN_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait.' },
})

export const apiLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_API_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded.' },
})

export const activateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: config.RATE_LIMIT_ACTIVATE_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Activation limit reached. Try again later.' },
})
