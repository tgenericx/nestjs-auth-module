import { BaseUser } from '../user-model';

/**
 * Safe user data exposed in authentication responses
 * Excludes sensitive fields like password
 */
export type AuthUserData = Omit<BaseUser, 'password' | 'googleId'>;
