/**
 * Input data for refreshing access token
 */
export interface TokenRefreshInput {
  refreshToken: string;
}

/**
 * Output data from refreshing tokens
 */
export interface TokenRefreshOutput {
  accessToken: string;
  refreshToken: string;
}
