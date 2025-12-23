import { Injectable, Optional } from '@nestjs/common';
import { TokenService } from './token.service';
import { RefreshTokenService } from './refresh-token.service';
import type { BaseUser, TokenPair, BaseRefreshTokenEntity, AuthResponse } from '../interfaces';

@Injectable()
export class AuthJwtService<
  RT extends BaseRefreshTokenEntity = BaseRefreshTokenEntity,
> {
  constructor(
    private readonly tokenService: TokenService,
    @Optional()
    private readonly refreshTokenService?: RefreshTokenService<RT>,
  ) { }

  /**
   * Generate access token only
   */
  generateAccessToken(userId: BaseUser['id']): string {
    return this.tokenService.generateAccessToken(userId);
  }

  /**
   * Generate both access and refresh tokens
   * Returns only access token if refresh tokens are not enabled
   */
  async generateTokens(userId: BaseUser['id']): Promise<TokenPair> {
    const accessToken = this.tokenService.generateAccessToken(userId);

    if (!this.refreshTokenService) {
      return { accessToken };
    }

    const refreshToken = await this.refreshTokenService.createRefreshToken(userId);

    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * Refresh both access and refresh tokens
   * Only available if refresh tokens are enabled
   */
  async refreshTokens(oldRefreshToken: string): Promise<AuthResponse> {
    if (!this.refreshTokenService) {
      throw new Error('Refresh tokens are not enabled');
    }
    const userId = await this.refreshTokenService.validateAndConsumeRefreshToken(oldRefreshToken);

    const refreshToken = await this.refreshTokenService.createRefreshToken(userId);
    const accessToken = this.tokenService.generateAccessToken(userId);
    return {
      user: {
        userId
      },
      tokens: {
        accessToken,
        refreshToken,
      }
    };
  }

  /**
   * Revoke a specific refresh token
   */
  async revokeToken(tokenId: string): Promise<void> {
    if (!this.refreshTokenService) {
      throw new Error('Refresh tokens are not enabled');
    }

    return this.refreshTokenService.revokeToken(tokenId);
  }

  /**
   * Revoke all refresh tokens for a user (logout all devices)
   */
  async revokeAllTokens(userId: string): Promise<void> {
    if (!this.refreshTokenService) {
      throw new Error('Refresh tokens are not enabled');
    }

    return this.refreshTokenService.revokeAllTokens(userId);
  }
}
