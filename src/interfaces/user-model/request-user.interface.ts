/**
 * Minimal, safe user data stored in the request object after authentication
 * This is what gets attached to HTTP requests and passed to controllers
 */
export interface RequestUser {
  userId: string;
  roles: string[];
}
