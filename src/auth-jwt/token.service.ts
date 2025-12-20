import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import type { BaseUser, JwtAuthConfig, JwtPayload, TokenPair } from '../interfaces';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtAuthConfig,
  ) { }

  generateAccessToken(userId: BaseUser['id']): string {
    const payload: JwtPayload = { sub: userId, type: 'access' };
    const { secret, privateKey, signOptions } = this.config.accessToken;

    return this.jwtService.sign(payload, {
      ...signOptions,
      secret: secret,
      privateKey: privateKey,
    });
  }

  generateRefreshToken(userId: BaseUser['id']): string {
    const payload: JwtPayload = { sub: userId, type: 'refresh' };
    const { secret, privateKey, signOptions } = this.config.refreshToken;

    return this.jwtService.sign(payload, {
      ...signOptions,
      secret: secret,
      privateKey: privateKey,
    });
  }

  generateTokens(userId: BaseUser['id']): TokenPair {
    return {
      accessToken: this.generateAccessToken(userId),
      refreshToken: this.generateRefreshToken(userId),
    };
  }
}
