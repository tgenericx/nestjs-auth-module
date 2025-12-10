import { Injectable, Inject, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { TokenResponseDto } from '../dto/token-response.dto';
import type { IUserRepository } from '../interfaces/user-repository.interface';
import { IEmailService } from '../interfaces/email-service.interface';
import { PasswordService } from './password.service';
import { TokenService } from './token.service';
import { AUTH_MODULE_CONFIG, USER_REPOSITORY, EMAIL_SERVICE } from '../auth.constants';
import type { IAuthModuleConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class AuthService {
  constructor(
    @Inject(USER_REPOSITORY) private readonly userRepository: IUserRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: IEmailService | null,
    @Inject(AUTH_MODULE_CONFIG) private readonly config: IAuthModuleConfig,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
  ) { }

  async register(dto: RegisterDto): Promise<TokenResponseDto> {
    // Validate password
    const validation = this.passwordService.validate(dto.password, this.config.password);
    if (!validation.valid) {
      throw new BadRequestException(validation.errors);
    }

    // Check if user exists
    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new BadRequestException('User with this email already exists');
    }

    // Hash password and create user
    const passwordHash = await this.passwordService.hash(dto.password);
    const user = await this.userRepository.create(dto.email, passwordHash);

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Store hashed refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(refreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async login(dto: LoginDto): Promise<TokenResponseDto> {
    // Find user
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    if (!user.passwordHash) {
      throw new UnauthorizedException('Please log in using Google');
    }

    const isPasswordValid = await this.passwordService.compare(
      dto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user is active
    if (user.isActive === false) {
      throw new UnauthorizedException('Account is inactive');
    }

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Store hashed refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(refreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refresh(refreshToken: string): Promise<TokenResponseDto> {
    // Verify token
    const payload = await this.tokenService.verifyToken(refreshToken);

    // Find user
    const user = await this.userRepository.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    // Validate refresh token against stored hash
    if (!user.hashedRefreshToken) {
      throw new UnauthorizedException('Invalid token');
    }

    const isRefreshTokenValid = await this.tokenService.compareToken(
      refreshToken,
      user.hashedRefreshToken,
    );

    if (!isRefreshTokenValid) {
      throw new UnauthorizedException('Invalid token');
    }

    // Generate new tokens
    const newAccessToken = this.tokenService.generateAccessToken(user);
    const newRefreshToken = this.tokenService.generateRefreshToken(user);

    // Update stored refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(newRefreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  async logout(userId: string): Promise<void> {
    await this.userRepository.updateRefreshToken(userId, null);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      // Don't reveal if user exists
      return;
    }

    const resetToken = this.passwordService.generateResetToken();

    if (this.emailService) {
      await this.emailService.sendPasswordResetEmail(email, resetToken);
    }

    // Note: You'll need to store the reset token with expiry
    // This is left to the consuming app to implement
  }

  async googleLogin(googleProfile: any): Promise<TokenResponseDto> {
    // Check if user exists by Google ID
    let user = await this.userRepository.findByGoogleId(googleProfile.googleId);

    if (!user) {
      // Check if user exists by email
      user = await this.userRepository.findByEmail(googleProfile.email);

      if (user) {
        // User exists with this email but no Google ID
        // This means they registered with email/password
        // You might want to link the accounts or throw an error
        throw new BadRequestException('An account with this email already exists. Please log in with your password.');
      }

      // Create new user from Google profile
      user = await this.userRepository.createFromGoogle(
        googleProfile.email,
        googleProfile.googleId,
        googleProfile,
      );
    }

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Store hashed refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(refreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }
}
