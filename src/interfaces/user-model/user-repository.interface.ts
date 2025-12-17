import { AuthUser } from './user.interface';

/**
 * Contract for consumer's User Repository implementation
 * Must be implemented by consumers to provide data persistence
 */
export interface UserRepository<User extends Partial<AuthUser>> {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  findByGoogleId(googleId: string): Promise<User | null>;
  create(data: Partial<User>): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
}
