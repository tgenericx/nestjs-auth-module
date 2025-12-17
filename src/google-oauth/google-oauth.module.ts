import { DynamicModule, Module } from '@nestjs/common';
import { GoogleStrategy } from './google.strategy';
import { GoogleAuthService } from './google.service';
import { GoogleAuthGuard } from './google-auth.guard';

@Module({})
export class GoogleOAuthModule {
  static forRoot(): DynamicModule {
    return {
      module: GoogleOAuthModule,
      providers: [GoogleStrategy, GoogleAuthGuard, GoogleAuthService],
      exports: [GoogleAuthService, GoogleAuthGuard],
    };
  }
}
