# @nahnah/nestjs-auth-module

A flexible, production-ready authentication module for NestJS applications. This module provides JWT-based authentication with optional Google OAuth integration, password hashing with Argon2, role-based authorization, and comprehensive token management.

## Features

* 🔐 **JWT Authentication** - Secure access and refresh tokens
* 🔑 **Password Management** - Argon2 hashing with configurable validation rules
* 👥 **Role-Based Authorization** - Decorator-based role guards
* 🌐 **Google OAuth** - Optional Google authentication integration
* 🛡️ **Security First** - Refresh token rotation, token blacklisting, and secure password policies
* 📧 **Email Service** - Extensible email service for password reset and verification
* 🔌 **Database Agnostic** - Works with any database through repository pattern
* 🎯 **Decorators** - Easy-to-use decorators for controllers (`@CurrentUser`, `@Public`, `@Roles`)

## Installation

```bash
npm install @nahnah/nestjs-auth-module
# or
yarn add @nahnah/nestjs-auth-module
# or
pnpm add @nahnah/nestjs-auth-module
```

## Peer Dependencies

This module requires the following peer dependencies:

```json
{
  "@nestjs/common": "^11.0.1",
  "@nestjs/core": "^11.0.1",
  "@nestjs/jwt": "^11.0.2",
  "@nestjs/passport": "^11.0.5",
  "@nestjs/platform-express": "^11.0.1",
  "argon2": "^0.44.0",
  "class-transformer": "^0.5.1",
  "class-validator": "^0.14.3",
  "passport-jwt": "^4.0.1",
  "passport": "^0.7.0",
  "passport-google-oauth20": "^2.0.0",
  "reflect-metadata": "^0.2.2",
  "rxjs": "^7.8.1"
}
```

## Quick Start

### 1. Create User Repository

```typescript
// user.repository.ts
import { Injectable } from '@nestjs/common';
import { IUserRepository, IAuthUser } from '@nahnah/nestjs-auth-module';

@Injectable()
export class UserRepository implements IUserRepository {
  async findByEmail(email: string): Promise<IAuthUser | null> {}
  async findById(id: string): Promise<IAuthUser | null> {}
  async findByGoogleId(googleId: string): Promise<IAuthUser | null> {}
  async create(email: string, passwordHash: string): Promise<IAuthUser> {}
  async createFromGoogle(email: string, googleId: string, profile: any): Promise<IAuthUser> {}
  async updatePassword(userId: string, passwordHash: string): Promise<void> {}
  async updateRefreshToken(userId: string, refreshToken: string | null): Promise<void> {}
}
```

### 2. Configure the Module

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@nahnah/nestjs-auth-module';
import { UserRepository } from './user.repository';

@Module({
  imports: [
    AuthModule.forRoot({
      jwt: {
        secret: process.env.JWT_SECRET || 'your-secret-key',
        accessTokenSignOptions: { expiresIn: '15m' },
        refreshTokenSignOptions: { expiresIn: '7d' },
      },
      password: {
        minLength: 8,
        requireSpecialChar: true,
        requireNumber: true,
        requireUppercase: true,
      },
      userRepository: UserRepository,
      // google: {
      //   clientID: process.env.GOOGLE_CLIENT_ID,
      //   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      //   callbackURL: process.env.GOOGLE_CALLBACK_URL,
      // },
    }),
  ],
})
export class AppModule {}
```

### 3. Create Auth Controller

```typescript
// auth.controller.ts
import { Controller, Post, Body, UseGuards, Get, Req } from '@nestjs/common';
import {
  AuthService,
  LoginDto,
  RegisterDto,
  RefreshTokenDto,
  TokenResponseDto,
  JwtAuthGuard,
  CurrentUser,
  Public,
  Roles,
  RolesGuard,
} from '@nahnah/nestjs-auth-module';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() dto: RegisterDto): Promise<TokenResponseDto> {
    return this.authService.register(dto);
  }

  @Public()
  @Post('login')
  async login(@Body() dto: LoginDto): Promise<TokenResponseDto> {
    return this.authService.login(dto);
  }

  @Public()
  @Post('refresh')
  async refresh(@Body() dto: RefreshTokenDto): Promise<TokenResponseDto> {
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('logout')
  async logout(@CurrentUser('id') userId: string): Promise<void> {
    return this.authService.logout(userId);
  }

  @Get('me')
  async getProfile(@CurrentUser() user: any) {
    return user;
  }

  @Roles('admin')
  @UseGuards(RolesGuard)
  @Get('admin-only')
  async adminOnly() {
    return { message: 'Admin access granted' };
  }

  @Public()
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {}

  @Public()
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(@Req() req) {
    return this.authService.googleLogin(req.user);
  }
}
```

### 4. Set up Global Guards

```typescript
// main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { JwtAuthGuard } from '@nahnah/nestjs-auth-module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalGuards(new JwtAuthGuard());
  await app.listen(3000);
}
bootstrap();
```

## Configuration Options

```typescript
interface IAuthModuleConfig {
  jwt: {
    secret: string;
    accessTokenSignOptions: JwtSignOptions;
    refreshTokenSignOptions: JwtSignOptions;
  };
  password?: {
    minLength?: number;
    requireSpecialChar?: boolean;
    requireNumber?: boolean;
    requireUppercase?: boolean;
  };
  google?: {
    clientID: string;
    clientSecret: string;
    callbackURL: string;
  };
  userRepository: any;
  emailService?: any;
}
```

## Decorators

### `@CurrentUser()`

```typescript
@Get('profile')
async getProfile(@CurrentUser() user: any) {
  return user;
}

@Get('profile-id')
async getProfileId(@CurrentUser('id') userId: string) {
  return { userId };
}
```

### `@Public()`

```typescript
@Public()
@Get('public-route')
async publicRoute() {
  return { message: 'Anyone can access this' };
}
```

### `@Roles()`

```typescript
@Roles('admin', 'moderator')
@Get('admin-route')
async adminRoute() {
  return { message: 'Admin or moderator access' };
}
```

## Services

* **AuthService** — Registration, login, refresh tokens, logout, Google login
* **TokenService** — Token generation & verification
* **PasswordService** — Argon2 hashing and validation

## Email Service Integration (Optional)

```typescript
// email.service.ts
import { Injectable } from '@nestjs/common';
import { IEmailService } from '@nahnah/nestjs-auth-module';

@Injectable()
export class EmailService implements IEmailService {
  async sendPasswordResetEmail(email: string, token: string): Promise<void> {}
  async sendVerificationEmail(email: string, token: string): Promise<void> {}
}
```

## Extending the Module

### Custom User Interface

```typescript
import { IAuthUser } from '@nahnah/nestjs-auth-module';

export interface IAppUser extends IAuthUser {
  firstName?: string;
  lastName?: string;
  createdAt: Date;
  updatedAt: Date;
}
```

### Custom Guards

```typescript
import { Injectable } from '@nestjs/common';
import { JwtAuthGuard } from '@nahnah/nestjs-auth-module';

@Injectable()
export class CustomAuthGuard extends JwtAuthGuard {}
```

## Security Considerations

1. Use strong JWT secrets
2. Set reasonable token expirations
3. Rate-limit auth endpoints
4. Use HTTPS
5. Consider IP whitelisting and device fingerprinting
6. Store refresh tokens securely

## Development

```bash
git clone <repository-url>
pnpm install
pnpm run build
pnpm test
```

## License

MIT

