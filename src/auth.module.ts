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
import { IUserRepository } from './interfaces/user-repository.interface';
import { IEmailService } from './interfaces/email-service.interface';
import { AUTH_MODULE_CONFIG, USER_REPOSITORY, EMAIL_SERVICE } from './auth.constants';

/**
 * Options for registering the Auth module synchronously
 * 
 * @example
 * ```typescript
 * AuthModule.forRoot({
 *   config: {
 *     jwt: {
 *       secret: process.env.JWT_SECRET,
 *       accessTokenSignOptions: { expiresIn: '15m' },
 *       refreshTokenSignOptions: { expiresIn: '7d' }
 *     }
 *   },
 *   userRepository: UserService,
 *   emailService: EmailService // optional
 * })
 * ```
 */
export interface AuthModuleOptions {
  /** JWT and authentication configuration */
  config: IAuthModuleConfig;

  /** 
   * Service class that implements IUserRepository interface
   * This service must be decorated with @Injectable()
   */
  userRepository: Type<IUserRepository>;

  /** 
   * Optional service class that implements IEmailService interface
   * This service must be decorated with @Injectable()
   */
  emailService?: Type<IEmailService>;
}

/**
 * Options for registering the Auth module asynchronously
 * Useful when configuration depends on other modules or async operations
 * 
 * @example
 * ```typescript
 * AuthModule.forRootAsync({
 *   imports: [ConfigModule],
 *   useFactory: (configService: ConfigService) => ({
 *     jwt: {
 *       secret: configService.get('JWT_SECRET'),
 *       accessTokenSignOptions: { expiresIn: '15m' },
 *       refreshTokenSignOptions: { expiresIn: '7d' }
 *     }
 *   }),
 *   inject: [ConfigService],
 *   userRepository: UserService,
 *   emailService: EmailService
 * })
 * ```
 */
export interface AuthModuleAsyncOptions {
  /** Modules to import that are required by the factory */
  imports?: any[];

  /** 
   * Factory function that returns auth configuration
   * Can be async if configuration requires async operations
   */
  useFactory: (...args: any[]) => Promise<IAuthModuleConfig> | IAuthModuleConfig;

  /** Dependencies to inject into the factory function */
  inject?: any[];

  /** 
   * Service class that implements IUserRepository interface
   * This service must be decorated with @Injectable()
   */
  userRepository: Type<IUserRepository>;

  /** 
   * Optional service class that implements IEmailService interface
   * This service must be decorated with @Injectable()
   */
  emailService?: Type<IEmailService>;
}


@Module({})
export class AuthModule {
  /**
   * Register the Auth module with synchronous configuration
   * Use this when your configuration is available immediately
   */
  static forRoot(options: AuthModuleOptions): DynamicModule {
    // Validate required options
    this.validateOptions(options);

    const providers: Provider[] = [
      // Config provider
      {
        provide: AUTH_MODULE_CONFIG,
        useValue: options.config,
      },
      {
        provide: USER_REPOSITORY,
        useClass: options.userRepository,
      },
      ...(options.emailService
        ? [{
          provide: EMAIL_SERVICE,
          useClass: options.emailService,
        }]
        : [{
          provide: EMAIL_SERVICE,
          useValue: null,
        }]),
      AuthService,
      TokenService,
      PasswordService,
      JwtStrategy,
      JwtAuthGuard,
      RolesGuard,
    ];

    // Conditionally add Google OAuth providers
    if (options.config.google) {
      providers.push(GoogleStrategy, GoogleAuthGuard);
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

  /**
   * Register the Auth module with asynchronous configuration
   * Use this when your configuration depends on other modules (like ConfigModule)
   */
  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    // Validate required options
    this.validateAsyncOptions(options);

    const providers = [
      // Config provider (async)
      {
        provide: AUTH_MODULE_CONFIG,
        useFactory: options.useFactory,
        inject: options.inject || [],
      },
      {
        provide: USER_REPOSITORY,
        useClass: options.userRepository,
      },
      ...(options.emailService
        ? [{
          provide: EMAIL_SERVICE,
          useClass: options.emailService,
        }]
        : [{
          provide: EMAIL_SERVICE,
          useValue: null,
        }]),
      AuthService,
      TokenService,
      PasswordService,
      JwtStrategy,
      JwtAuthGuard,
      RolesGuard,
      {
        provide: GoogleStrategy,
        useFactory: (config: IAuthModuleConfig) => {
          return config.google ? new GoogleStrategy(config) : null;
        },
        inject: [AUTH_MODULE_CONFIG],
      },
      {
        provide: GoogleAuthGuard,
        useFactory: (config: IAuthModuleConfig) => {
          return config.google ? new GoogleAuthGuard() : null;
        },
        inject: [AUTH_MODULE_CONFIG],
      },
    ];

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

  /**
   * Validate synchronous configuration options
   */
  private static validateOptions(options: AuthModuleOptions): void {
    if (!options.config) {
      throw new Error('AuthModule: "config" is required');
    }
    if (!options.config.jwt) {
      throw new Error('AuthModule: "config.jwt" is required');
    }
    if (!options.config.jwt.secret) {
      throw new Error('AuthModule: "config.jwt.secret" is required');
    }
    if (!options.userRepository) {
      throw new Error('AuthModule: "userRepository" is required');
    }
  }

  /**
   * Validate asynchronous configuration options
   */
  private static validateAsyncOptions(options: AuthModuleAsyncOptions): void {
    if (!options.useFactory) {
      throw new Error('AuthModule: "useFactory" is required for async configuration');
    }
    if (!options.userRepository) {
      throw new Error('AuthModule: "userRepository" is required');
    }
  }
}
