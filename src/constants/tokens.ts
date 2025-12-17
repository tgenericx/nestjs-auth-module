export const AUTH_CONFIG = Symbol('AUTH_CONFIG');

export const AUTH_CAPABILITIES = Object.freeze({
  JWT: Symbol('JWT_CONFIG'),
  CREDENTIALS: Symbol('CREDENTIALS_CONFIG'),
  GOOGLE: Symbol('GOOGLE_CONFIG'),
});

export const PROVIDERS = Object.freeze({
  USER_REPOSITORY: Symbol('USER_REPOSITORY'),
});
