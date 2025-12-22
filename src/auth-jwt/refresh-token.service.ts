import {
  Injectable,
  Inject,
  UnauthorizedException,
  BadRequestException
} from '@nestjs/common';
import { PROVIDERS, AUTH_CAPABILITIES } from '../constants';
import { HashService } from '../utils/hash.service';
import type {
  RefreshTokenRepository,
  TokenRefreshInput,
  TokenRefreshOutput,
  JwtAuthConfig,
  BaseRefreshTokenEntity,
} from '../interfaces';
import { TokenService } from './token.service';
import { createHash } from 'crypto';

@Injectable()
export class RefreshTokenService<RT extends BaseRefreshTokenEntity = BaseRefreshTokenEntity> {
  constructor(
    @Inject(PROVIDERS.REFRESH_TOKEN_REPOSITORY)
    private readonly refreshTokenRepo: RefreshTokenRepository<RT>,
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly jwtConfig: JwtAuthConfig,
    private readonly hashService: HashService,
    private readonly token: TokenService,
  ) { }

  /**
   * Generate and persist a new refresh token
   * Called after login/registration/token refresh
   */
  async createRefreshToken(userId: string): Promise<string> {
    const plainToken = this.hashService.generateSecureToken(32);
    const token = createHash('sha256').update(plainToken).digest('hex');

    if (!this.jwtConfig.refreshToken) {
      throw new Error('refresh token must be configured to use refresh token service')
    }
    const expiresIn = this.jwtConfig.refreshToken.expiresIn;
    const expiresAt = this.calculateExpirationDate(expiresIn);

    await this.refreshTokenRepo.create({
      userId,
      token,
      expiresAt,
    } as Omit<RT, 'id'>);

    return plainToken;
  }

  /**
   * Validate refresh token and generate new token pair
   * Implements one-time use: deletes old token after validation
   */
  async refreshTokens(input: TokenRefreshInput): Promise<TokenRefreshOutput> {
    const { refreshToken: plainToken } = input;

    if (!plainToken) {
      throw new BadRequestException('Refresh token is required');
    }

    // Hash incoming token to compare with stored hash
    const tokenHash = createHash('sha256').update(plainToken).digest('hex');

    // Find token in database
    const storedToken = await this.refreshTokenRepo.findByTokenHash(tokenHash);

    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check expiration
    if (new Date() > storedToken.expiresAt) {
      await this.refreshTokenRepo.delete(storedToken.id);
      throw new UnauthorizedException('Refresh token expired');
    }

    // Verify token hash (defense in depth)
    const isValid = await this.hashService.verify(plainToken, storedToken.token);
    if (!isValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // ONE-TIME USE: Delete used token immediately
    await this.refreshTokenRepo.delete(storedToken.id);

    // Generate new token pair
    const accessToken = this.token.generateAccessToken(storedToken.userId);
    const newRefreshToken = await this.createRefreshToken(storedToken.userId);

    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  }

  /**
   * Revoke a specific refresh token
   */
  async revokeToken(tokenId: string): Promise<void> {
    await this.refreshTokenRepo.delete(tokenId);
  }

  /**
   * Revoke all refresh tokens for a user (logout all devices)
   */
  async revokeAllTokens(userId: string): Promise<void> {
    await this.refreshTokenRepo.deleteAllForUser(userId);
  }

  /**
   * Calculate expiration date from JWT expiresIn format
   */
  private calculateExpirationDate(expiresIn: string | number): Date {
    const now = new Date();

    if (typeof expiresIn === 'number') {
      return new Date(now.getTime() + expiresIn * 1000);
    }

    // Parse string formats like '7d', '24h', '60m'
    const match = expiresIn.match(/^(\d+)([dhms])$/);
    if (!match) {
      throw new Error(`Invalid expiresIn format: ${expiresIn}`);
    }

    const [, value, unit] = match;
    const num = parseInt(value, 10);

    const multipliers = { d: 86400, h: 3600, m: 60, s: 1 };
    const seconds = num * multipliers[unit as keyof typeof multipliers];

    return new Date(now.getTime() + seconds * 1000);
  }
}
