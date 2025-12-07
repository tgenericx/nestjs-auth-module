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
          signOptions: {
            ...config.jwt.accessTokenSignOptions
          },
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
}
