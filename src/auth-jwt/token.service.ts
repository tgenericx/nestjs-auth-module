import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import type { BaseUser, JwtAuthConfig, JwtPayload } from '../interfaces';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtAuthConfig,
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
}
