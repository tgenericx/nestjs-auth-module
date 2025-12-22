import { ModuleMetadata, FactoryProvider } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { AuthModuleConfig } from './auth-module-config.interface';
import { AuthUser, UserRepository } from '../user-model';
import { BaseRefreshTokenEntity, RefreshTokenRepository } from '../refresh-token';

/**
 * Asynchronous configuration options for the AuthModule
 * Allows consumers to provide configuration via factories
 */
export interface AuthModuleAsyncOptions<
  User extends Partial<AuthUser> = Partial<AuthUser>,
  RT extends BaseRefreshTokenEntity = BaseRefreshTokenEntity,
>
  extends
  Pick<ModuleMetadata, 'imports'>,
  Pick<FactoryProvider<AuthModuleConfig>, 'useFactory' | 'inject'> {
  userRepository: Type<UserRepository<User>>;
  refreshTokenRepository?: Type<RefreshTokenRepository<RT>>;
  enabledCapabilities: ('credentials' | 'google')[];
}
