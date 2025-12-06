import { JwtSignOptions } from "@nestjs/jwt";

export interface IJwtConfig {
  secret: string;
  accessTokenSignOptions: JwtSignOptions;
  refreshTokenSignOptions: JwtSignOptions;
}

export interface IPasswordConfig {
  minLength?: number;
  requireSpecialChar?: boolean;
  requireNumber?: boolean;
  requireUppercase?: boolean;
}

export interface IAuthModuleConfig {
  jwt: IJwtConfig;
  password?: IPasswordConfig;
  userRepository: any; // Provider token
  emailService?: any; // Provider token (optional)
}
