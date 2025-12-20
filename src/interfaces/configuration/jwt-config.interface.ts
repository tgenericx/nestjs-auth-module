import { JwtSignOptions } from '@nestjs/jwt';

type SymmetricKey = {
  secret: string | Buffer;
  publicKey?: never;
  privateKey?: never
};

type AsymmetricKey = {
  secret?: never;
  publicKey: string | Buffer;
  privateKey: string | Buffer
};

export interface JwtAuthSignOptions extends JwtSignOptions {
  expiresIn: NonNullable<JwtSignOptions['expiresIn']>;
}

export type TokenConfig = (SymmetricKey | AsymmetricKey) & {
  /**
   * MUST contain expiresIn, algorithm, etc.
   * This is now required to prevent "immortal tokens" by accident.
   */
  signOptions: JwtAuthSignOptions;
};

/**
 * Configuration for JWT token generation and validation
 */
export interface JwtAuthConfig {
  accessToken: TokenConfig;
  refreshToken: TokenConfig;
}
