import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { JwtAuthConfig, JwtPayload, RequestUser } from '../interfaces';
import { AUTH_CAPABILITIES } from '../constants';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtAuthConfig,
  ) {
    const key = config.accessToken.secret || config.accessToken.publicKey;

    if (!key) {
      throw new Error('JWT Strategy: No secret or publicKey provided in configuration');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: key,
    });
  }

  async validate(payload: JwtPayload): Promise<RequestUser> {
    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token payload: missing sub');
    }

    if (payload.type !== 'access') {
      throw new UnauthorizedException('Invalid token type: expected access token');
    }

    return {
      userId: payload.sub,
    };
  }
}
