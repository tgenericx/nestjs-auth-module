import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import type {
  AuthUser,
  BaseUser,
  JwtConfig,
  JwtPayload,
  TokenPair,
} from '../interfaces';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtConfig,
  ) {}

  generateAccessToken(user: BaseUser): string {
    const payload: JwtPayload = {
      sub: user.id,
      roles: user.roles,
    };

    return this.jwtService.sign(payload, {
      ...this.config.accessTokenSignOptions,
    });
  }

  generateRefreshToken(user: { id: string }): string {
    const payload = { sub: user.id };

    return this.jwtService.sign(payload, {
      ...this.config.refreshTokenSignOptions,
    });
  }

  generateTokens(user: AuthUser): TokenPair {
    return {
      accessToken: this.generateAccessToken(user),
      refreshToken: this.generateRefreshToken({ id: user.id }),
    };
  }

  async verifyAccessToken(token: string): Promise<JwtPayload> {
    try {
      return await this.jwtService.verifyAsync<JwtPayload>(
        token,
        this.config.accessTokenSignOptions as JwtVerifyOptions,
      );
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Access token has expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid access token');
      }
      throw new UnauthorizedException('Token verification failed');
    }
  }

  async verifyRefreshToken(token: string): Promise<{ sub: string }> {
    try {
      return await this.jwtService.verifyAsync<{ sub: string }>(
        token,
        this.config.refreshTokenSignOptions as JwtVerifyOptions,
      );
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Refresh token has expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid refresh token');
      }
      throw new UnauthorizedException('Token verification failed');
    }
  }

  decodeToken(token: string): JwtPayload | null {
    try {
      return this.jwtService.decode(token) as JwtPayload;
    } catch {
      return null;
    }
  }
}
