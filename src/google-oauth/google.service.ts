import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import type {
  AuthResponse,
  AuthUser,
  RequestUser,
  UserRepository,
} from '../interfaces';
import { PROVIDERS } from '../constants';
import { AuthJwtService } from '../auth-jwt/auth-jwt.service';

@Injectable()
export class GoogleAuthService<User extends Partial<AuthUser>> {
  constructor(
    @Inject(PROVIDERS.USER_REPOSITORY)
    private readonly userRepository: UserRepository<User>,
    private readonly authJwtService: AuthJwtService,
  ) {}

  /**
   * Complete the Google OAuth flow by generating JWT tokens.
   * Call this in your callback controller after Passport attaches user to request.
   */
  async handleOAuthCallback(requestUser: RequestUser): Promise<AuthResponse> {
    // Fetch full user data
    const user = await this.userRepository.findById(requestUser.userId);
    if (!user || !user.id) {
      throw new UnauthorizedException('User not found after OAuth');
    }

    const { accessToken, refreshToken } =
      await this.authJwtService.generateTokens(user.id);

    return {
      user: {
        userId: user.id,
      },
      accessToken,
      refreshToken,
    };
  }

  /**
   * Unlink Google account from user.
   * Useful if user wants to remove Google login but keep password login.
   */
  async unlinkGoogleAccount(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Check if user has another way to login
    if (!user.password && user.googleId) {
      throw new UnauthorizedException(
        'Cannot unlink Google account. Please set a password first.',
      );
    }

    // Unlink Google
    await this.userRepository.update(userId, {
      googleId: null,
    } as Partial<User>);

    return { message: 'Google account unlinked successfully' };
  }

  /**
   * Check if a user has Google OAuth linked.
   */
  async isGoogleLinked(userId: string): Promise<boolean> {
    const user = await this.userRepository.findById(userId);
    return !!user?.googleId;
  }
}
