import { Injectable, Inject, Optional } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import type { BaseRefreshTokenEntity, BaseUser, JwtAuthConfig, JwtPayload, TokenPair } from '../interfaces';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class TokenService<
  RT extends BaseRefreshTokenEntity = BaseRefreshTokenEntity,
> {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtAuthConfig,
    @Optional()
    private readonly refresh?: RefreshTokenService<RT>,
  ) { }

  generateAccessToken(userId: BaseUser['id']): string {
    const payload: JwtPayload = { sub: userId, type: 'access' };
    const { signOptions } = this.config.accessToken;

    const keyOptions =
      'secret' in this.config.accessToken
        ? { secret: this.config.accessToken.secret }
        : { privateKey: this.config.accessToken.privateKey };

    return this.jwtService.sign(payload, {
      ...signOptions,
      ...keyOptions,
    });
  }

  async generateTokens(userId: BaseUser['id']): Promise<TokenPair> {
    const accessToken = this.generateAccessToken(userId);
    if (!this.refresh) {
      return { accessToken }
    }

    return {
      accessToken,
      refreshToken: await this.refresh.createRefreshToken(userId),
    };
  }
}
