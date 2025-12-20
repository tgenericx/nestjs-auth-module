import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { JwtConfig, JwtPayload, RequestUser } from '../interfaces';
import { AUTH_CAPABILITIES } from '../constants';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtConfig,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: (request, rawJwtToken, done) => {
        const options = config.accessTokenSignOptions;

        // If secret exists, use it (symmetric)
        if (options.secret) {
          return done(null, options.secret as string | Buffer);
        }

        // If publicKey exists, use it (asymmetric)
        if (options.publicKey) {
          const publicKey = options.publicKey;

          if (typeof publicKey === 'string' || Buffer.isBuffer(publicKey)) {
            return done(null, publicKey);
          }

          try {
            return done(null, publicKey as any);
          } catch (error) {
            return done(new Error('Invalid public key format for JWT verification'));
          }
        }

        return done(new Error('JWT verification key not configured'));
      },
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
