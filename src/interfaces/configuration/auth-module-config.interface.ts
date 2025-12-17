import { JwtConfig } from './jwt-config.interface';
import { CredentialsAuthConfig } from './credentials-auth-config.interface';
import { GoogleOAuthConfig } from './google-oauth-config.interface';

/**
 * Main configuration for the authentication module
 * Optional properties determine which authentication strategies are enabled
 */
export interface AuthModuleConfig {
  jwt: JwtConfig;
  credentials?: CredentialsAuthConfig;
  google?: GoogleOAuthConfig;
}
