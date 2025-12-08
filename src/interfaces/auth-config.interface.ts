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

export interface IGoogleOAuthConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

export interface IAuthModuleConfig {
  jwt: IJwtConfig;
  password?: IPasswordConfig;
  google?: IGoogleOAuthConfig;
}
