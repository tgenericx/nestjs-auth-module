import { RequestUser } from '../user-model';
import { TokenPair } from './token-pair.interface';

/**
 * Standard response format for authentication operations
 */
export interface AuthResponse {
  user: RequestUser;
  tokens: TokenPair;
}
