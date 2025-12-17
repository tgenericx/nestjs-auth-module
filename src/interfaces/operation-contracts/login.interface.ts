import { BaseUser } from "../user-model/user.interface";

/**
 * Input data required for login operation
 */
export interface LoginInput {
  email: string;
  password: string;
}

/**
 * Response data returned from login operation
 */
export interface LoginResponse {
  user: BaseUser;
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
}
