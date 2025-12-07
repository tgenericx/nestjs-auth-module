import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './services/auth.service';
import { TokenService } from './services/token.service';
import { PasswordService } from './services/password.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { IAuthModuleConfig } from './interfaces/auth-config.interface';
import { AUTH_MODULE_CONFIG, USER_REPOSITORY, EMAIL_SERVICE } from './auth.constants';

export interface AuthModuleAsyncOptions {
  imports?: any[];
  inject?: any[];
  useFactory: (...args: any[]) => Promise<IAuthModuleConfig> | IAuthModuleConfig;
}

@Module({})
export class AuthModule {
  static forRoot(config: IAuthModuleConfig): DynamicModule {
    const configProvider: Provider = {
      provide: AUTH_MODULE_CONFIG,
      useValue: config,
    };

    const userRepositoryProvider: Provider = {
      provide: USER_REPOSITORY,
      useExisting: config.userRepository,
    };

    const emailServiceProvider: Provider = {
      provide: EMAIL_SERVICE,
      useExisting: config.emailService || null,
    };

    // Only add Google strategy if config is provided
    const strategies: Provider[] = [
      JwtStrategy,
      ...(config.google ? [GoogleStrategy] : []),
    ];

    const guards: Provider[] = [
      JwtAuthGuard,
      RolesGuard,
      ...(config.google ? [GoogleAuthGuard] : []),
    ];

    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: config.jwt.secret,
          signOptions: { ...config.jwt.accessTokenSignOptions },
        }),
      ],
      providers: [
        configProvider,
        userRepositoryProvider,
        emailServiceProvider,
        AuthService,
        TokenService,
        PasswordService,
        ...strategies,
        ...guards,
      ],
      exports: [
        AuthService,
        TokenService,
        PasswordService,
        ...guards,
      ],
    };
  }

  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    const asyncConfigProvider: Provider = {
      provide: AUTH_MODULE_CONFIG,
      useFactory: options.useFactory,
      inject: options.inject || [],
    };

    return {
      module: AuthModule,
      imports: [
        ...(options.imports || []),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          imports: options.imports,
          inject: options.inject,
          useFactory: async (...args: any[]) => {
            const config = await options.useFactory(...args);
            return {
              secret: config.jwt.secret,
              signOptions: { ...config.jwt.accessTokenSignOptions },
            };
          },
        }),
      ],
      providers: [
        asyncConfigProvider,
        {
          provide: USER_REPOSITORY,
          useFactory: async (...args: any[]) => {
            const config = await options.useFactory(...args);
            return config.userRepository;
          },
          inject: options.inject || [],
        },
        {
          provide: EMAIL_SERVICE,
          useFactory: async (...args: any[]) => {
            const config = await options.useFactory(...args);
            return config.emailService || null;
          },
          inject: options.inject || [],
        },
        AuthService,
        TokenService,
        PasswordService,
        JwtStrategy,
        JwtAuthGuard,
        RolesGuard,
        // Conditionally add Google strategy via a factory
        {
          provide: 'GOOGLE_STRATEGY_FACTORY',
          useFactory: async (...args: any[]) => {
            const config = await options.useFactory(...args);
            if (config.google) {
              return GoogleStrategy;
            }
            return null;
          },
          inject: options.inject || [],
        },
      ],
      exports: [
        AuthService,
        TokenService,
        PasswordService,
        JwtAuthGuard,
        RolesGuard,
      ],
    };
  }
}
