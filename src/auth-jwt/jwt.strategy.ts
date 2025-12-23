import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { JwtAuthConfig, JwtPayload, RequestUser } from '../interfaces';
import { AUTH_CAPABILITIES } from '../constants';
import {
  getVerificationKey,
  validateTokenConfig,
} from '../interfaces/configuration/jwt-config.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtAuthConfig,
  ) {
    validateTokenConfig(config.accessToken, 'JWT accessToken');

    const secretOrKey = getVerificationKey(config.accessToken);

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey,
      algorithms: config.accessToken.signOptions.algorithm
        ? [config.accessToken.signOptions.algorithm]
        : undefined,
      issuer: config.accessToken.signOptions.issuer,
      audience: config.accessToken.signOptions.audience,
    });
  }

  async validate(payload: JwtPayload): Promise<RequestUser> {
    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token payload: missing sub');
    }

    if (payload.type !== 'access') {
      throw new UnauthorizedException(
        'Invalid token type: expected access token',
      );
    }

    return {
      userId: payload.sub,
    };
  }
}
