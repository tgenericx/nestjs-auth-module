import { BaseUser } from '../user/user.interface';

/**
 * Safe user data exposed in authentication responses
 * Excludes sensitive fields like password
 */
export type AuthUserData = Omit<BaseUser, 'password' | 'googleId'>;
