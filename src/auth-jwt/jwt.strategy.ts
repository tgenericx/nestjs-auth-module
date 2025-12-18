import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, SecretOrKeyProvider, Strategy } from 'passport-jwt';
import type { JwtConfig, JwtPayload, RequestUser } from '../interfaces';
import { AUTH_CAPABILITIES } from '../constants';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtConfig,
  ) {
    const secretOrKeyProvider: SecretOrKeyProvider = (
      request,
      rawJwtToken,
      done,
    ) => {
      const secretOrKey =
        config.accessTokenSignOptions.secret ??
        config.accessTokenSignOptions.privateKey;

      done(secretOrKey);
    };
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider,
    });
  }

  async validate(payload: JwtPayload): Promise<RequestUser> {
    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }
    return {
      userId: payload.sub,
    };
  }
}
