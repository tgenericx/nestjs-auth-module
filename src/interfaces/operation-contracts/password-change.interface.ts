/**
 * Input data for changing user password (requires current password)
 */
export interface PasswordChangeInput {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

/**
 * Input data for setting/resetting password (admin or forgot password flow)
 */
export interface PasswordSetInput {
  userId: string;
  newPassword: string;
}
