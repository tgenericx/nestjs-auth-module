import { ModuleMetadata, FactoryProvider } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { AuthModuleConfig } from './auth-module-config.interface';
import { AuthUser, UserRepository } from '../user-model';

/**
 * Asynchronous configuration options for the AuthModule
 * Allows consumers to provide configuration via factories
 */
export interface AuthModuleAsyncOptions<User extends Partial<AuthUser> = any>
  extends Pick<ModuleMetadata, 'imports'>,
  Pick<FactoryProvider<AuthModuleConfig>, 'useFactory' | 'inject'> {
  userRepository: Type<UserRepository<User>>;
}
