import { AuthResponse } from "../authentication";
import { RequestUser } from "../user-model";

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
