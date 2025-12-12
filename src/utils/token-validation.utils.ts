import { IJwtConfig } from '../interfaces/auth-config.interface';

/**
 * Converts JWT expiry string to milliseconds
 * Supports: '15m', '7d', '24h', '60s', etc.
 */
export function parseExpiryToMs(expiry: string | number | undefined): number | null {
  if (!expiry) return null;
  if (typeof expiry === 'number') return expiry * 1000;

  const matches = expiry.match(/^(\d+)([smhd])$/);
  if (!matches) return null;

  const value = parseInt(matches[1], 10);
  const unit = matches[2];

  const multipliers: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return value * multipliers[unit];
}

/**
 * Validates JWT configuration to ensure proper token separation
 * Throws errors for critical misconfigurations
 */
export function validateJwtConfig(config: IJwtConfig): void {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate that both expiresIn are set
  const accessExpiry = config.accessTokenSignOptions?.expiresIn;
  const refreshExpiry = config.refreshTokenSignOptions?.expiresIn;

  if (!accessExpiry) {
    errors.push('Access token expiresIn must be specified');
  }

  if (!refreshExpiry) {
    errors.push('Refresh token expiresIn must be specified');
  }

  if (accessExpiry && refreshExpiry) {
    const accessMs = parseExpiryToMs(accessExpiry);
    const refreshMs = parseExpiryToMs(refreshExpiry);

    if (accessMs === null) {
      errors.push(`Invalid access token expiresIn format: "${accessExpiry}". Use formats like "15m", "1h", "7d"`);
    }

    if (refreshMs === null) {
      errors.push(`Invalid refresh token expiresIn format: "${refreshExpiry}". Use formats like "15m", "1h", "7d"`);
    }

    if (accessMs !== null && refreshMs !== null) {
      // Critical: Refresh must be longer than access
      if (refreshMs <= accessMs) {
        errors.push(
          `Refresh token expiry (${refreshExpiry}) must be longer than access token expiry (${accessExpiry}). ` +
          `This is a critical security requirement.`
        );
      }

      // Warning: Access token too long
      const thirtyMinutes = 30 * 60 * 1000;
      if (accessMs > thirtyMinutes) {
        warnings.push(
          `Access token expiry (${accessExpiry}) is longer than 30 minutes. ` +
          `Consider using shorter-lived access tokens (5-15 minutes) for better security.`
        );
      }

      // Warning: Refresh token too short
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      if (refreshMs < sevenDays) {
        warnings.push(
          `Refresh token expiry (${refreshExpiry}) is shorter than 7 days. ` +
          `Consider using longer-lived refresh tokens (7-30 days) for better user experience.`
        );
      }

      // Warning: Tokens are too similar (within 10% difference)
      const difference = refreshMs - accessMs;
      const percentDifference = (difference / accessMs) * 100;
      if (percentDifference < 10) {
        warnings.push(
          `Access and refresh token expiry times are very similar (${accessExpiry} vs ${refreshExpiry}). ` +
          `Refresh tokens should typically be much longer-lived than access tokens.`
        );
      }
    }
  }

  // Check for audience separation (recommended but not required)
  const accessAud = config.accessTokenSignOptions?.audience;
  const refreshAud = config.refreshTokenSignOptions?.audience;

  if (accessAud && refreshAud && accessAud === refreshAud) {
    warnings.push(
      `Access and refresh tokens have the same audience ("${accessAud}"). ` +
      `Consider using different audiences (e.g., "api" vs "refresh") for enhanced security.`
    );
  }

  // Throw if there are errors
  if (errors.length > 0) {
    throw new Error(
      `JWT Configuration Validation Failed:\n${errors.map(e => `  - ${e}`).join('\n')}`
    );
  }

  // Log warnings in development
  if (warnings.length > 0 && process.env.NODE_ENV !== 'production') {
    console.warn('\n⚠️  JWT Configuration Warnings:');
    warnings.forEach(w => console.warn(`  - ${w}`));
    console.warn('');
  }
}

/**
 * Provides recommended default configurations
 */
export const RECOMMENDED_JWT_CONFIG = {
  development: {
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
  },
  production: {
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '30d',
  },
} as const;
