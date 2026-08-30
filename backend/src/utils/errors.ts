export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
    public readonly code?: string,
  ) { super(message); this.name = 'AppError' }
}

export const Errors = {
  UNAUTHORIZED:      () => new AppError(401, 'Please sign in again'),
  FORBIDDEN:         () => new AppError(403, 'You do not have access to this action'),
  NOT_FOUND:         (r = 'Resource') => new AppError(404, `${r} was not found`),
  INTERNAL:          () => new AppError(500, 'Something went wrong on our side. Try again'),
  INVALID_CREDS:     () => new AppError(401, 'Username or password is incorrect'),
  ACCOUNT_SUSPENDED: () => new AppError(403, 'This account is suspended. Contact support'),
  LICENSE_INVALID:   () => new AppError(403, 'License is invalid or expired'),
  REPLAY_DETECTED:   () => new AppError(400, 'Stale login request. Refresh and try again'),
  DEVICE_LIMIT:      () => new AppError(403, 'Too many devices on this license'),
  DEVICE_LIMIT_EXCEEDED: () => new AppError(403, 'Device limit exceeded for this license', 'DEVICE_LIMIT'),
  DEVICE_VERIFICATION_REQUIRED: () => new AppError(403, 'This device needs verification', 'DEVICE_VERIFY'),
  SESSION_REVOKED:   () => new AppError(401, 'Session ended. Sign in again', 'REVOKED'),
  ATTEST_FAILED:     () => new AppError(403, 'Security check failed. Restart the loader', 'ATTEST_FAIL'),
  HARDWARE_VERIFICATION_REQUIRED: () => new AppError(403, 'Hardware verification required', 'DEVICE_VERIFY'),
  DEVICE_FINGERPRINT_MISMATCH: () => new AppError(403, 'Device fingerprint mismatch', 'FP_MISMATCH'),
  CHALLENGE_EXPIRED: () => new AppError(400, 'Verification challenge expired', 'CHALLENGE_EXPIRED'),
  INVALID_CHALLENGE: () => new AppError(400, 'Invalid verification challenge', 'INVALID_CHALLENGE'),
}
