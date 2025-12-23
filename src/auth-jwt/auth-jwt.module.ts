import { DynamicModule, Module, Provider } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import { TokenService } from './token.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RefreshTokenService } from './refresh-token.service';
import { AuthJwtService } from './auth-jwt.service';
import { HashService } from '../utils/hash.service';
import { JwtAuthConfig } from '../interfaces';

@Module({})
export class AuthJwtModule {
  static forRoot(options?: { enableRefreshTokens?: boolean }): DynamicModule {
    const providers: Provider[] = [
      JwtStrategy,
      JwtAuthGuard,
      HashService,
      TokenService,
    ];

    const exports: (string | symbol | Provider)[] = [
      JwtAuthGuard,
      HashService,
      TokenService,
    ];

    if (options?.enableRefreshTokens) {
      providers.push(RefreshTokenService);
      exports.push(RefreshTokenService);
    }

    providers.push(AuthJwtService);
    exports.push(AuthJwtService);

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
