import { DynamicModule, Module, Provider } from '@nestjs/common';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import { TokenService } from './token.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RefreshTokenService } from './refresh-token.service';
import { HashService } from '../utils/hash.service';
import { JwtAuthConfig } from '../interfaces';

@Module({})
export class AuthJwtModule {
  static forRoot(options?: { enableRefreshTokens?: boolean }): DynamicModule {
    const providers: Provider[] = [JwtStrategy, JwtAuthGuard, HashService];
    const exports: (string | symbol | Provider)[] = [JwtAuthGuard, HashService];

    if (options?.enableRefreshTokens) {
      providers.push(RefreshTokenService);
      exports.push(RefreshTokenService);
    }

    // Always provide TokenService, but conditionally inject RefreshTokenService
    providers.push({
      provide: TokenService,
      useFactory: (
        jwtService,
        config,
        refreshTokenService?,
      ) => new TokenService(jwtService, config, refreshTokenService),
      inject: [
        JwtService,
        AUTH_CAPABILITIES.JWT,
        ...(options?.enableRefreshTokens ? [RefreshTokenService] : []),
      ],
    });
    exports.push(TokenService);

    return {
      module: AuthJwtModule,
      imports: [
        JwtModule.registerAsync({
          inject: [AUTH_CAPABILITIES.JWT],
          useFactory: (config: JwtAuthConfig) => ({
            ...config.accessToken,
          }),
        }),
      ],
      providers,
      exports,
    };
  }
}
