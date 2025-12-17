import {
  DynamicModule,
  Module,
} from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AUTH_CAPABILITIES } from '../constants';
import { TokenService } from './token.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';
import { JwtConfig } from 'src/interfaces';

@Module({})
export class AuthJwtModule {
  static forRoot(): DynamicModule {
    return {
      module: AuthJwtModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          useFactory: (jwtConfig: JwtConfig) => ({
            ...jwtConfig.accessTokenSignOptions
          }),
          inject: [AUTH_CAPABILITIES.JWT],
        }),
      ],
      providers: [
        TokenService,
        JwtStrategy,
        JwtAuthGuard,
        RolesGuard,
      ],
      exports: [
        TokenService,
        JwtAuthGuard,
        RolesGuard,
      ],
    };
  }
}
