import { RequestUser } from '../user/request-user.interface';
import { AuthResponse } from '../auth/auth-response.interface';

/**
 * Response from Google OAuth callback operation
 */
export interface GoogleOAuthCallbackResponse extends AuthResponse { }

/**
 * Input for Google OAuth callback (user data from Passport)
 */
export interface GoogleOAuthCallbackInput {
  requestUser: RequestUser;
}
