import { DynamicModule, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import { TokenService } from './token.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwtAuthConfig } from '../interfaces';

@Module({})
export class AuthJwtModule {
  static forRoot(): DynamicModule {
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
      providers: [TokenService, JwtStrategy, JwtAuthGuard],
      exports: [TokenService, JwtAuthGuard],
    };
  }
}
