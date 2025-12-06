import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
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
      secret: this.config.jwt.secret,
      ...this.config.jwt.accessTokenSignOptions
    });
  }

  generateRefreshToken(user: IAuthUser): string {
    const payload: JwtPayloadDto = {
      sub: user.id,
      email: user.email,
    };

    return this.jwtService.sign(payload, {
      secret: this.config.jwt.secret,
      ...this.config.jwt.refreshTokenSignOptions
    });
  }

  async verifyToken(token: string): Promise<JwtPayloadDto> {
    try {
      return this.jwtService.verify(token, {
        secret: this.config.jwt.secret,
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async hashToken(token: string): Promise<string> {
    const argon2 = require('argon2');
    return argon2.hash(token);
  }

  async compareToken(token: string, hash: string): Promise<boolean> {
    const argon2 = require('argon2');
    try {
      return await argon2.verify(hash, token);
    } catch (error) {
      return false;
    }
  }
}
