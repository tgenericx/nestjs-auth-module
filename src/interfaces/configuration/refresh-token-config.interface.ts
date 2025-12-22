/**
 * Configuration for refresh token behavior
 */
export interface RefreshTokenConfig {
  /**
   * Length of random bytes for refresh token (default: 32 = 256 bits)
   */
  tokenLength?: number;

  /**
   * Refresh token lifetime in seconds (default: 7 days)
   */
  expiresIn: number;
}
