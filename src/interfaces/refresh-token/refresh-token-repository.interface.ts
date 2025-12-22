import { BaseRefreshTokenEntity } from "./refresh-token.interface";

/**
 * Contract for refresh token storage (database, Redis, etc.)
 * Must be implemented by consumers
 */
export interface RefreshTokenRepository<RT extends BaseRefreshTokenEntity = BaseRefreshTokenEntity> {
  /**
   * Store a new refresh token (hashed)
   * @returns Created refresh token entity
   */
  create(data: Omit<RT, 'id'>): Promise<RT>;
  /**
   * Find refresh token by its hash
   * Used during token refresh to validate the token
   */
  findByTokenHash(token: string): Promise<RT | null>;

  /**
   * Delete a specific refresh token (after use or revocation)
   * Implements one-time use pattern
   */
  delete(id: string): Promise<void>;

  /**
   * Delete all refresh tokens for a user
   * Useful for "logout all devices" or account security
   */
  deleteAllForUser(userId: string): Promise<void>;

  /**
   * Optional: Delete expired tokens (for cleanup jobs)
   */
  deleteExpired?(): Promise<void>;
}
