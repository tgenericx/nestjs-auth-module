/**
 * Structure of JWT token payload
 */
export interface JwtPayload {
  sub: string;
  type: 'access';
}
