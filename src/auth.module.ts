import { DynamicModule, Module, Provider } from '@nestjs/common';
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

export interface AuthModuleOptions {
  config: IAuthModuleConfig;
  userRepository: Provider;
  emailService?: Provider;
}

export interface AuthModuleAsyncOptions {
  imports?: any[];
  useFactory: (...args: any[]) => Promise<IAuthModuleConfig> | IAuthModuleConfig;
  inject?: any[];
  userRepository: Provider;
  emailService?: Provider;
}

@Module({})
export class AuthModule {
  static forRoot(options: AuthModuleOptions): DynamicModule {
    const providers: Provider[] = [
      {
        provide: AUTH_MODULE_CONFIG,
        useValue: options.config,
      },
      options.userRepository,
      options.emailService || {
        provide: EMAIL_SERVICE,
        useValue: null,
      },
      AuthService,
      TokenService,
      PasswordService,
      JwtStrategy,
      JwtAuthGuard,
      RolesGuard,
    ];

    // Only add Google strategy if Google config is provided
    if (options.config.google) {
      providers.push(GoogleStrategy);
      providers.push(GoogleAuthGuard);
    }

    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: options.config.jwt.secret,
          signOptions: { ...options.config.jwt.accessTokenSignOptions },
        }),
      ],
      providers,
      exports: [
        AuthService,
        TokenService,
        PasswordService,
        JwtAuthGuard,
        RolesGuard,
        ...(options.config.google ? [GoogleAuthGuard] : []),
        JwtModule,
      ],
    };
  }

  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    const providers: Provider[] = [
      {
        provide: AUTH_MODULE_CONFIG,
        useFactory: options.useFactory,
        inject: options.inject || [],
      },
      options.userRepository,
      options.emailService || {
        provide: EMAIL_SERVICE,
        useValue: null,
      },
      AuthService,
      TokenService,
      PasswordService,
      JwtStrategy,
      JwtAuthGuard,
      RolesGuard,
    ];

    providers.push(GoogleStrategy);
    providers.push(GoogleAuthGuard);

    const jwtModule = JwtModule.registerAsync({
      imports: options.imports || [],
      useFactory: async (...args: any[]) => {
        const config = await options.useFactory(...args);
        return {
          secret: config.jwt.secret,
          signOptions: { ...config.jwt.accessTokenSignOptions },
        };
      },
      inject: options.inject || [],
    });

    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        jwtModule,
        ...(options.imports || []),
      ],
      providers,
      exports: [
        AuthService,
        TokenService,
        PasswordService,
        JwtAuthGuard,
        RolesGuard,
        GoogleAuthGuard,
        JwtModule,
      ],
    };
  }
}
