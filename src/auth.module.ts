import { DynamicModule, Module, Provider, Global } from '@nestjs/common';
import {
  AuthModuleAsyncOptions,
  AuthModuleConfig,
  AuthUser,
  BaseRefreshTokenEntity,
} from './interfaces';
import { AUTH_CONFIG, AUTH_CAPABILITIES, PROVIDERS } from './constants';
import { AuthJwtModule } from './auth-jwt/auth-jwt.module';
import { GoogleOAuthModule } from './google-oauth/google-oauth.module';
import { CredentialsAuthModule } from './credentials-auth/credentials-auth.module';

@Global()
@Module({})
export class AuthModule {
  static forRootAsync<
    User extends Partial<AuthUser> = any,
    RT extends BaseRefreshTokenEntity = BaseRefreshTokenEntity,
  >(options: AuthModuleAsyncOptions<User, RT>): DynamicModule {
    const configProvider: Provider = {
      provide: AUTH_CONFIG,
      useFactory: options.useFactory,
      inject: options.inject || [],
    };

    const userRepositoryProvider: Provider = {
      provide: PROVIDERS.USER_REPOSITORY,
      useClass: options.userRepository,
    };

    const jwtConfigProvider: Provider = {
      provide: AUTH_CAPABILITIES.JWT,
      useFactory: (config: AuthModuleConfig) => config.jwt,
      inject: [AUTH_CONFIG],
    };

    const credentialsConfigProvider: Provider = {
      provide: AUTH_CAPABILITIES.CREDENTIALS,
      useFactory: (config: AuthModuleConfig) =>
        options.enabledCapabilities.includes('credentials')
          ? config.credentials
          : undefined,
      inject: [AUTH_CONFIG],
    };

    const googleConfigProvider: Provider = {
      provide: AUTH_CAPABILITIES.GOOGLE,
      useFactory: (config: AuthModuleConfig) =>
        options.enabledCapabilities.includes('google')
          ? config.google
          : undefined,
      inject: [AUTH_CONFIG],
    };

    const providers: Provider[] = [
      configProvider,
      userRepositoryProvider,
      jwtConfigProvider,
      credentialsConfigProvider,
      googleConfigProvider,
    ];

    // Determine if refresh tokens are enabled
    const enableRefreshTokens = !!options.refreshTokenRepository;

    const imports = [
      ...(options.imports || []),
      AuthJwtModule.forRoot({ enableRefreshTokens }),
    ];

    const exports = [
      AUTH_CONFIG,
      AUTH_CAPABILITIES.JWT,
      PROVIDERS.USER_REPOSITORY,
      AuthJwtModule,
    ];

    // Add refresh token repository if provided
    if (enableRefreshTokens) {
      const refreshTokenRepoProvider: Provider = {
        provide: PROVIDERS.REFRESH_TOKEN_REPOSITORY,
        useClass: options.refreshTokenRepository!,
      };
      providers.push(refreshTokenRepoProvider);
      exports.push(PROVIDERS.REFRESH_TOKEN_REPOSITORY);
    }

    if (options.enabledCapabilities.includes('credentials')) {
      imports.push(CredentialsAuthModule.forRoot());
      exports.push(AUTH_CAPABILITIES.CREDENTIALS, CredentialsAuthModule);
    } else {
      exports.push(AUTH_CAPABILITIES.CREDENTIALS);
    }

    if (options.enabledCapabilities.includes('google')) {
      imports.push(GoogleOAuthModule.forRoot());
      exports.push(AUTH_CAPABILITIES.GOOGLE, GoogleOAuthModule);
    } else {
      exports.push(AUTH_CAPABILITIES.GOOGLE);
    }

    return {
      module: AuthModule,
      global: true,
      imports,
      providers,
      exports,
    };
  }
}
