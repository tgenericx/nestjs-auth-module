import { IAuthUser } from "./auth-user.interface";

export interface IUserRepository {
  findByEmail(email: string): Promise<IAuthUser | null>;
  findById(id: string): Promise<IAuthUser | null>;
  create(email: string, passwordHash: string): Promise<IAuthUser>;
  updatePassword(userId: string, passwordHash: string): Promise<void>;
  updateRefreshToken(userId: string, refreshToken: string | null): Promise<void>;
}
