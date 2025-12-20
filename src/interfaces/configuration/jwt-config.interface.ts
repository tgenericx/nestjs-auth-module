import { JwtModuleOptions } from '@nestjs/jwt';

/**
 * Configuration for JWT token generation and validation
 */
export interface JwtConfig {
  accessTokenSignOptions: JwtModuleOptions;
  refreshTokenSignOptions: JwtModuleOptions;
}
