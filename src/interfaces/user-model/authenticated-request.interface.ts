import { Request } from 'express';
import { RequestUser } from './request-user.interface';

/**
 * Extended Express Request with authenticated user data
 */
export interface AuthenticatedRequest extends Request {
  user: RequestUser;
}
