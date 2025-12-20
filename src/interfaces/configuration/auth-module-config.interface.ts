import { CredentialsAuthConfig } from './credentials-auth-config.interface';
import { GoogleOAuthConfig } from './google-oauth-config.interface';
import { JwtAuthConfig } from './jwt-config.interface';

/**
 * Main configuration for the authentication module
 * Optional properties determine which authentication strategies are enabled
 */
export interface AuthModuleConfig {
  jwt: JwtAuthConfig;
  credentials?: CredentialsAuthConfig;
  google?: GoogleOAuthConfig;
}
