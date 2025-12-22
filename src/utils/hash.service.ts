import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';

/**
 * Generic hashing service used by both password and refresh token features
 * Keeps PasswordService backward compatible but extracts shared logic
 */
@Injectable()
export class HashService {
  /**
   * Hash any sensitive string (passwords, tokens, etc.)
   */
  async hash(value: string): Promise<string> {
    return argon2.hash(value);
  }

  /**
   * Verify a value against its hash
   */
  async verify(value: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, value);
    } catch {
      return false;
    }
  }

  /**
   * Generate cryptographically secure random token
   * @param bytes - Number of random bytes (default: 32)
   * @returns Hex-encoded token string
   */
  generateSecureToken(bytes: number = 32): string {
    return randomBytes(bytes).toString('hex');
  }
}
