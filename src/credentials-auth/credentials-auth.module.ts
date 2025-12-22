import { DynamicModule, Module, Provider } from '@nestjs/common';
import { PasswordService } from './password.service';
import { CredentialsAuthService } from './credentials-auth.service';
import { HashService } from '../utils/hash.service';

@Module({})
export class CredentialsAuthModule {
  static forRoot(options?: { enableRefreshTokens?: boolean }): DynamicModule {
    const providers: Provider[] = [PasswordService, CredentialsAuthService];

    if (!options?.enableRefreshTokens) {
      providers.push(HashService);
    }

    return {
      module: CredentialsAuthModule,
      providers,
      exports: [CredentialsAuthService, PasswordService],
    };
  }
}
