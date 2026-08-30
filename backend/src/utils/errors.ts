export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
    public readonly code?: string,
  ) { super(message); this.name = 'AppError' }
}

export const Errors = {
  UNAUTHORIZED:      () => new AppError(401, 'Unauthorized'),
  FORBIDDEN:         () => new AppError(403, 'Access denied'),
  NOT_FOUND:         (r = 'Resource') => new AppError(404, `${r} not found`),
  INTERNAL:          () => new AppError(500, 'Internal server error'),
  INVALID_CREDS:     () => new AppError(401, 'Invalid credentials'),
  ACCOUNT_SUSPENDED: () => new AppError(403, 'Account suspended'),
  LICENSE_INVALID:   () => new AppError(403, 'License invalid or expired'),
  REPLAY_DETECTED:   () => new AppError(400, 'Replay detected'),
  DEVICE_LIMIT:      () => new AppError(403, 'Device limit reached'),
}
