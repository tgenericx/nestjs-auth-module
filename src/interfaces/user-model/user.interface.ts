/**
 * Base mandatory fields for any user in the authentication system
 */
export interface BaseUser {
  id: string;
  email: string;
  isEmailVerified: boolean;
}

/**
 * Fields specific to password-based authentication
 */
export interface CredentialsUser {
  password?: string | null;
}

/**
 * Fields specific to Google OAuth authentication
 */
export interface GoogleUser {
  googleId?: string | null;
}

/**
 * The complete user entity type combining all possible authentication methods
 * Consumers implement concrete types that intersect with only the features they need
 */
export type AuthUser = BaseUser & CredentialsUser & GoogleUser;
