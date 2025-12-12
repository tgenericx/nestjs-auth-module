import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { JwtPayloadDto } from '../dto/jwt-payload.dto';
import { IAuthUser } from '../interfaces/auth-user.interface';
import { AUTH_MODULE_CONFIG } from '../auth.constants';
import type { IAuthModuleConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_MODULE_CONFIG) private readonly config: IAuthModuleConfig,
  ) { }

  generateAccessToken(user: IAuthUser): string {
    const payload: JwtPayloadDto = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
    };

    return this.jwtService.sign(payload, {
      ...this.config.jwt.accessTokenSignOptions
    });
  }

  generateRefreshToken(user: IAuthUser): string {
    const payload: JwtPayloadDto = {
      sub: user.id,
      email: user.email,
    };

    return this.jwtService.sign(payload, {
      ...this.config.jwt.refreshTokenSignOptions
    });
  }

  async verifyToken(token: string, isRefreshToken: boolean = false): Promise<JwtPayloadDto> {
    try {
      const signOptions = isRefreshToken
        ? this.config.jwt.refreshTokenSignOptions
        : this.config.jwt.accessTokenSignOptions;

      const verifyOptions: JwtVerifyOptions = {
        secret: signOptions.secret,
        algorithms: signOptions.algorithm ? [signOptions.algorithm] : undefined,
        audience: signOptions.audience as any,
        issuer: signOptions.issuer,
        ignoreExpiration: false,
      };

      return this.jwtService.verify(token, verifyOptions);
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async hashToken(token: string): Promise<string> {
    return argon2.hash(token);
  }

  async compareToken(token: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, token);
    } catch (error) {
      return false;
    }
  }
}
