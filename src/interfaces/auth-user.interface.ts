export interface IAuthUser {
  id: string;
  email: string;
  passwordHash?: string;
  hashedRefreshToken?: string | null;
  roles?: string[];
  isActive?: boolean;
}
