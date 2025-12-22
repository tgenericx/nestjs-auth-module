/**
 * Refresh token record stored in database
 */
export interface BaseRefreshTokenEntity {
  /**
   * Primary key
   */
  id: string;

  /**
   * Hashed refresh token (argon2 hash)
   */
  token: string;

  /**
   * User ID this token belongs to
   */
  userId: string;

  /**
   * When this token expires
   */
  expiresAt: Date;
}
