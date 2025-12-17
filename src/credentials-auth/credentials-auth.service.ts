import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { AUTH_CAPABILITIES, PROVIDERS } from '../constants/tokens';
import type {
  AuthResponse,
  AuthUser,
  CredentialsAuthConfig,
  LoginInput,
  LoginResponse,
  PasswordChangeInput,
  PasswordSetInput,
  RegistrationInput,
  UserRepository,
} from '../interfaces';
import { PasswordService } from './password.service';
import { TokenService } from '../auth-jwt/token.service';

@Injectable()
export class CredentialsAuthService<User extends Partial<AuthUser>> {
  constructor(
    @Inject(PROVIDERS.USER_REPOSITORY)
    private readonly userRepository: UserRepository<User>,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
    @Inject(AUTH_CAPABILITIES.CREDENTIALS)
    private readonly config: CredentialsAuthConfig | undefined,
  ) {
    // Check if credentials auth is enabled
    if (!config) {
      throw new Error(
        'CredentialsAuthModule is imported but credentials config is not provided. ' +
        'Either remove the module or provide credentials config in AuthModule.forRootAsync()',
      );
    }
  }

  /**
   * Register a new user with email and password.
   * accepts any DTO that implements CredentialsCreateInput
   */
  async register<UserData extends RegistrationInput = RegistrationInput>(
    userData: UserData,
  ): Promise<AuthResponse> {
    const existingUser = await this.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await this.passwordService.hash(userData.password);

    // Create user with all properties from dto (including extra fields)
    const user = await this.userRepository.create({
      ...userData,
      password: hashedPassword,
    } as unknown as Partial<User>);

    const tokens = this.tokenService.generateTokens(user as AuthUser);

    return {
      user: {
        id: user.id!,
        email: user.email!,
        roles: user.roles!,
        isEmailVerified: user.isEmailVerified!,
      },
      tokens,
    };
  }

  /**
   * Login with email and password.
   * Accepts any DTO that has email and password
   */
  async login<UserData extends LoginInput = LoginInput>(
    credentials: UserData,
  ): Promise<LoginResponse> {
    const user = await this.userRepository.findByEmail(credentials.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user has a password (might be OAuth-only user)
    if (!user.password) {
      throw new UnauthorizedException(
        'This account uses social login. Please login with Google.',
      );
    }

    // Verify password
    const isPasswordValid = await this.passwordService.verify(
      credentials.password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const tokens = this.tokenService.generateTokens(user as AuthUser);

    return {
      user: {
        id: user.id!,
        email: user.email!,
        roles: user.roles!,
        isEmailVerified: user.isEmailVerified!,
      },
      tokens,
    };
  }

  /**
   * Change user password (requires current password).
   */
  async changePassword(
    input: PasswordChangeInput,
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findById(input.userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user has a password
    if (!user.password) {
      throw new BadRequestException(
        'Cannot change password for OAuth-only accounts',
      );
    }

    // Verify current password
    const isCurrentPasswordValid = await this.passwordService.verify(
      input.currentPassword,
      user.password,
    );

    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    const isSamePassword = await this.passwordService.verify(
      input.newPassword,
      user.password,
    );
    if (isSamePassword) {
      throw new BadRequestException(
        'New password must be different from current password',
      );
    }

    // Hash new password
    const hashedPassword = await this.passwordService.hash(input.newPassword);

    await this.userRepository.update(input.userId, {
      password: hashedPassword,
    } as Partial<User>);

    return { message: 'Password changed successfully' };
  }

  /**
   * Set or reset password (admin operation or forgot password flow).
   * Does NOT require current password.
   */
  async setPassword(input: PasswordSetInput): Promise<{ message: string }> {
    // Find user
    const user = await this.userRepository.findById(input.userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const hashedPassword = await this.passwordService.hash(input.newPassword);

    // Update user
    await this.userRepository.update(input.userId, {
      password: hashedPassword,
    } as Partial<User>);

    return { message: 'Password set successfully' };
  }

  /**
   * Verify user's email (call this after email verification token is validated).
   */
  async verifyEmail(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isEmailVerified) {
      return { message: 'Email already verified' };
    }

    await this.userRepository.update(userId, {
      isEmailVerified: true,
    } as Partial<User>);

    return { message: 'Email verified successfully' };
  }

  /**
   * Validate user exists and is active (useful for token refresh).
   */
  async validateUser(userId: string): Promise<User> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  // TODO: Implement request password reset.
}
