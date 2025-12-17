import { DynamicModule, Module } from '@nestjs/common';
import { PasswordService } from './password.service';
import { CredentialsAuthService } from './credentials-auth.service';

@Module({})
export class CredentialsAuthModule {
  static forRoot(): DynamicModule {
    return {
      module: CredentialsAuthModule,
      providers: [
        PasswordService,
        CredentialsAuthService,
      ],
      exports: [
        CredentialsAuthService,
        PasswordService,
      ],
    };
  }
}
