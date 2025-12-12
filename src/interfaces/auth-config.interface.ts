import { JwtSignOptions } from "@nestjs/jwt";

export interface IJwtConfig {
  /**
   * Sign options for access tokens
   * Recommended: expiresIn between 5m-30m (e.g., '15m')
   * Should always be shorter than refresh token expiry
   */
  accessTokenSignOptions: JwtSignOptions;

  /**
   * Sign options for refresh tokens
   * Recommended: expiresIn between 7d-30d (e.g., '7d')
   * Must be longer than access token expiry
   */
  refreshTokenSignOptions: JwtSignOptions;
}

export interface IPasswordConfig {
  minLength?: number;
  requireSpecialChar?: boolean;
  requireNumber?: boolean;
  requireUppercase?: boolean;
}

export interface IGoogleOAuthConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

export interface IAuthModuleConfig {
  jwt: IJwtConfig;
  password?: IPasswordConfig;
  google?: IGoogleOAuthConfig;
}
