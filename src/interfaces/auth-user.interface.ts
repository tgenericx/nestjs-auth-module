export interface IAuthUser {
  id: string;
  email: string;
  passwordHash?: string;
  roles?: string[];
  isActive?: boolean;
}
