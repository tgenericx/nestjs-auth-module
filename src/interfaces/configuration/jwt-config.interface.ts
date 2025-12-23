import { JwtSignOptions } from '@nestjs/jwt';
import { RefreshTokenConfig } from './refresh-token-config.interface';

// ============================================================================
// OPTION 1: Explicit Factory Functions (Recommended)
// ============================================================================

export interface JwtAuthSignOptions extends JwtSignOptions {
  expiresIn: NonNullable<JwtSignOptions['expiresIn']>;
}

/**
 * Configuration for symmetric key (HS256, HS384, HS512)
 */
export interface SymmetricTokenConfig {
  type: 'symmetric';
  secret: string | Buffer;
  signOptions: JwtAuthSignOptions;
}

/**
 * Configuration for asymmetric keys (RS256, RS384, RS512, ES256, etc.)
 */
export interface AsymmetricTokenConfig {
  type: 'asymmetric';
  publicKey: string | Buffer;
  privateKey: string | Buffer;
  signOptions: JwtAuthSignOptions;
}

export type TokenConfig = SymmetricTokenConfig | AsymmetricTokenConfig;

/**
 * Configuration for JWT token generation and validation
 */
export interface JwtAuthConfig {
  accessToken: TokenConfig;
  refreshToken?: RefreshTokenConfig;
}

/**
 * Create symmetric key configuration (HS256/HS384/HS512)
 *
 * @example
 * ```ts
 * const config = createSymmetricTokenConfig({
 *   secret: process.env.JWT_SECRET,
 *   signOptions: {
 *     expiresIn: '15m',
 *     algorithm: 'HS256',
 *   }
 * });
 * ```
 */
export function createSymmetricTokenConfig(
  config: Omit<SymmetricTokenConfig, 'type'>,
): SymmetricTokenConfig {
  return {
    type: 'symmetric',
    ...config,
  };
}

/**
 * Create asymmetric key configuration (RS256/ES256/etc.)
 *
 * @example
 * ```ts
 * const config = createAsymmetricTokenConfig({
 *   publicKey: fs.readFileSync('./public.pem'),
 *   privateKey: fs.readFileSync('./private.pem'),
 *   signOptions: {
 *     expiresIn: '15m',
 *     algorithm: 'RS256',
 *   }
 * });
 * ```
 */
export function createAsymmetricTokenConfig(
  config: Omit<AsymmetricTokenConfig, 'type'>,
): AsymmetricTokenConfig {
  return {
    type: 'asymmetric',
    ...config,
  };
}

/**
 * Validate token configuration at runtime
 * Throws descriptive error if configuration is invalid
 */
export function validateTokenConfig(
  config: TokenConfig,
  configName: string,
): void {
  if (!config.signOptions?.expiresIn) {
    throw new Error(
      `${configName}: signOptions.expiresIn is required to prevent immortal tokens`,
    );
  }

  if (config.type === 'symmetric') {
    if (!config.secret) {
      throw new Error(
        `${configName}: secret is required for symmetric key configuration`,
      );
    }
  } else if (config.type === 'asymmetric') {
    if (!config.publicKey) {
      throw new Error(
        `${configName}: publicKey is required for asymmetric key configuration`,
      );
    }
    if (!config.privateKey) {
      throw new Error(
        `${configName}: privateKey is required for asymmetric key configuration`,
      );
    }
  } else {
    throw new Error(
      `${configName}: invalid type, must be 'symmetric' or 'asymmetric'`,
    );
  }
}

/**
 * Helper to extract the appropriate key from TokenConfig
 */
export function getVerificationKey(config: TokenConfig): string | Buffer {
  if (config.type === 'symmetric') {
    return config.secret;
  } else {
    return config.publicKey;
  }
}

/**
 * Helper to extract the signing key from TokenConfig
 */
export function getSigningKey(config: TokenConfig): string | Buffer {
  if (config.type === 'symmetric') {
    return config.secret;
  } else {
    return config.privateKey;
  }
}

export function isSymmetricConfig(
  config: TokenConfig,
): config is SymmetricTokenConfig {
  return config.type === 'symmetric';
}

export function isAsymmetricConfig(
  config: TokenConfig,
): config is AsymmetricTokenConfig {
  return config.type === 'asymmetric';
}
