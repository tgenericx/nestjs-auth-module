import { DynamicModule, Module, Provider, Global } from '@nestjs/common';
import {
  AuthModuleAsyncOptions,
  AuthModuleConfig,
  AuthUser,
} from './interfaces';
import {
  AUTH_CONFIG,
  AUTH_CAPABILITIES,
  PROVIDERS,
} from './constants';
import { AuthJwtModule } from './auth-jwt/auth-jwt.module';
import { GoogleOAuthModule } from './google-oauth/google-oauth.module';
import { CredentialsAuthModule } from './credentials-auth/credentials-auth.module';

@Global()
@Module({})
export class AuthModule {
  static forRootAsync<User extends Partial<AuthUser> = any>(
    options: AuthModuleAsyncOptions<User>
  ): DynamicModule {
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
      useFactory: (config: AuthModuleConfig) => config.credentials,
      inject: [AUTH_CONFIG],
    };

    const googleConfigProvider: Provider = {
      provide: AUTH_CAPABILITIES.GOOGLE,
      useFactory: (config: AuthModuleConfig) => config.google,
      inject: [AUTH_CONFIG],
    };

    return {
      module: AuthModule,
      global: true,
      imports: [
        ...(options.imports || []),
        // Import child modules
        AuthJwtModule.forRoot(),
        CredentialsAuthModule.forRoot(),
        GoogleOAuthModule.forRoot(),
      ],
      providers: [
        configProvider,
        userRepositoryProvider,
        jwtConfigProvider,
        credentialsConfigProvider,
        googleConfigProvider,
      ],
      exports: [
        // Export all providers so child modules can access them
        AUTH_CONFIG,
        AUTH_CAPABILITIES.JWT,
        AUTH_CAPABILITIES.CREDENTIALS,
        AUTH_CAPABILITIES.GOOGLE,
        PROVIDERS.USER_REPOSITORY,
        // Also export child module services for consumers
        AuthJwtModule,
        CredentialsAuthModule,
        GoogleOAuthModule,
      ],
    };
  }
}
