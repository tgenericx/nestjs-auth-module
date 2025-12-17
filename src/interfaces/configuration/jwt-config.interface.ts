import { JwtSignOptions } from '@nestjs/jwt';

/**
 * Configuration for JWT token generation and validation
 */
export interface JwtConfig {
  accessTokenSignOptions: JwtSignOptions;
  refreshTokenSignOptions: JwtSignOptions;
}
