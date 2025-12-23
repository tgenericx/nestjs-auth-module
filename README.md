<p align="center">
  <a href="https://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

<h1 align="center">@nahnah/nestjs-auth-module</h1>
<p align="center">A production-ready authentication module for NestJS featuring JWT, Passport strategies, and seamless integration.</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@nahnah/nestjs-auth-module" target="_blank"><img src="https://img.shields.io/npm/v/@nahnah/nestjs-auth-module.svg" alt="NPM Version" /></a>
  <a href="LICENSE" target="_blank"><img src="https://img.shields.io/npm/l/@nahnah/nestjs-auth-module.svg" alt="Package License" /></a>
  <a href="https://www.npmjs.com/package/@nahnah/nestjs-auth-module" target="_blank"><img src="https://img.shields.io/npm/dt/@nahnah/nestjs-auth-module.svg" alt="NPM Downloads" /></a>
  <a href="https://github.com/tgenericx/nestjs-auth-module/stargazers" target="_blank"><img src="https://img.shields.io/github/stars/tgenericx/nestjs-auth-module.svg" alt="GitHub Stars" /></a>
  <a href="https://github.com/tgenericx/nestjs-auth-module/network/members" target="_blank"><img src="https://img.shields.io/github/forks/tgenericx/nestjs-auth-module.svg" alt="GitHub Forks" /></a>
</p>

<p align="center">
  <a href="https://github.com/tgenericx/nestjs-auth-module/issues" target="_blank"><img src="https://img.shields.io/github/issues/tgenericx/nestjs-auth-module.svg" alt="GitHub Issues" /></a>
  <a href="https://github.com/tgenericx/nestjs-auth-module/pulls" target="_blank"><img src="https://img.shields.io/github/issues-pr/tgenericx/nestjs-auth-module.svg" alt="GitHub Pull Requests" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/TypeScript-⭐-blue.svg" alt="TypeScript" />
  <img src="https://img.shields.io/badge/NestJS-⭐-red.svg" alt="NestJS" />
  <img src="https://img.shields.io/badge/JWT-⭐-yellowgreen.svg" alt="JWT" />
  <img src="https://img.shields.io/badge/Passport-⭐-blueviolet.svg" alt="Passport" />
  <img src="https://img.shields.io/badge/Node.js-⭐-green.svg" alt="Node.js" />
</p>

---

## 📖 Overview

`@nahnah/nestjs-auth-module` is a **plug-and-play authentication solution for NestJS** designed for real-world production use.

It provides JWT-based authentication with access and refresh tokens, secure password hashing via **Argon2**, optional **Google OAuth**, and a clean **interface-driven architecture** that lets you bring your own database implementation.

If you want **speed without sacrificing structure**, this module is for you.

---

## ✨ Features

- 🔐 **JWT Authentication** — Access & refresh tokens with configurable lifetimes
- 🔑 **Secure Passwords** — Argon2 hashing out of the box
- 🌐 **Google OAuth 2.0** — Optional social authentication
- 🎯 **Clean DX** — `@Public()`, `@CurrentUser()` decorators
- 🔌 **Database-Agnostic** — Bring your own repository
- 📦 **Capability-Driven** — Enable only what you need
- 🛡️ **Fully Type-Safe** — Strict TypeScript support
- 🔄 **Refresh Token Rotation** — One-time use tokens with automatic cleanup
- ⚡ **Sensible Defaults** — Zero-config to get started fast

---

## 📦 Installation

### Want credentials?

```bash
npm install @nahnah/nestjs-auth-module argon2
```

### Want Google?

```bash
npm install @nahnah/nestjs-auth-module argon2 passport-google-oauth20
```

### Want both?

```bash
npm install @nahnah/nestjs-auth-module argon2 passport-google-oauth20
```

---

## 🚀 Quick Start

### 1️⃣ Implement User and Refresh Token Repositories

The module is **database-agnostic**. You must implement the `UserRepository` interface, and optionally the `RefreshTokenRepository` interface if you want refresh token support.

#### User Repository

```ts
import { Injectable } from '@nestjs/common';
import {
  UserRepository,
  GoogleUserRepository,
  AuthUser,
} from '@nahnah/nestjs-auth-module';

export interface User extends AuthUser {
  firstName?: string;
  lastName?: string;
  createdAt?: Date;
}

@Injectable()
export class UserRepositoryService implements GoogleUserRepository<User> {
  private users = new Map<string, User>();

  async findById(id: string) {
    return this.users.get(id) ?? null;
  }

  async findByEmail(email: string) {
    return [...this.users.values()].find((u) => u.email === email) ?? null;
  }

  async findByGoogleId(googleId: string) {
    return (
      [...this.users.values()].find((u) => u.googleId === googleId) ?? null
    );
  }

  async create(data: Partial<User>) {
    const user: User = {
      id: crypto.randomUUID(),
      email: data.email!,
      password: data.password ?? null,
      googleId: data.googleId ?? null,
      isEmailVerified: data.isEmailVerified ?? false,
      createdAt: new Date(),
    };

    this.users.set(user.id, user);
    return user;
  }

  async update(id: string, data: Partial<User>) {
    const user = await this.findById(id);
    if (!user) throw new Error('User not found');

    Object.assign(user, data);
    return user;
  }
}
```

#### Refresh Token Repository (Optional)

If you want refresh token support, implement the `RefreshTokenRepository` interface:

```ts
import { Injectable } from '@nestjs/common';
import {
  RefreshTokenRepository,
  BaseRefreshTokenEntity,
} from '@nahnah/nestjs-auth-module';

export interface RefreshToken extends BaseRefreshTokenEntity {
  createdAt: Date;
}

@Injectable()
export class RefreshTokenRepositoryService implements RefreshTokenRepository<RefreshToken> {
  private tokens = new Map<string, RefreshToken>();

  async create(data: Omit<RefreshToken, 'id'>) {
    const token: RefreshToken = {
      id: crypto.randomUUID(),
      ...data,
      createdAt: new Date(),
    };

    this.tokens.set(token.id, token);
    return token;
  }

  async findByTokenHash(tokenHash: string) {
    return [...this.tokens.values()].find((t) => t.token === tokenHash) ?? null;
  }

  async delete(id: string) {
    this.tokens.delete(id);
  }

  async deleteAllForUser(userId: string) {
    for (const [id, token] of this.tokens.entries()) {
      if (token.userId === userId) {
        this.tokens.delete(id);
      }
    }
  }

  async deleteExpired() {
    const now = new Date();
    for (const [id, token] of this.tokens.entries()) {
      if (token.expiresAt < now) {
        this.tokens.delete(id);
      }
    }
  }
}
```

---

### 2️⃣ Create Authentication Controllers

```ts
import { Controller, Post, Body, UseGuards, Get, Req } from '@nestjs/common';
import {
  CurrentUser,
  Public,
  GoogleAuthGuard,
  type AuthenticatedRequest,
  CredentialsAuthService,
  AuthResponse,
  RegistrationInput,
  LoginInput,
  GoogleAuthService,
  type RequestUser,
  AuthJwtService,
  TokenRefreshInput,
} from '@nahnah/nestjs-auth-module';
import { User } from './user-repository.service';

export class RegisterDto implements RegistrationInput {
  email: string;
  password: string;
}

export class LoginDto implements LoginInput {
  email: string;
  password: string;
}

export class RefreshTokenDto implements TokenRefreshInput {
  refreshToken: string;
}

@Controller('auth')
export class AuthController {
  constructor(
    private readonly credentialsAuth: CredentialsAuthService<User>,
    private readonly googleAuth: GoogleAuthService<User>,
    private readonly authJwt: AuthJwtService,
  ) {}

  @Public()
  @Post('register')
  async register(@Body() dto: RegisterDto): Promise<AuthResponse> {
    return this.credentialsAuth.register(dto);
  }

  @Public()
  @Post('login')
  async login(@Body() dto: LoginDto): Promise<AuthResponse> {
    return this.credentialsAuth.login(dto);
  }

  @Public()
  @Post('refresh')
  async refresh(@Body() dto: RefreshTokenDto): Promise<AuthResponse> {
    return this.authJwt.refreshTokens(dto.refreshToken);
  }

  @Get('me')
  async getProfile(@CurrentUser() user: RequestUser) {
    return user;
  }

  @Post('logout')
  async logout(@CurrentUser('userId') userId: string) {
    await this.authJwt.revokeAllTokens(userId);
    return { message: 'Logged out successfully' };
  }

  @Public()
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {}

  @Public()
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(@Req() req: AuthenticatedRequest) {
    return this.googleAuth.handleOAuthCallback(req.user);
  }
}
```

---

### 3️⃣ Configure the Auth Module

```ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import {
  AuthModule,
  JwtAuthGuard,
  createSymmetricTokenConfig,
} from '@nahnah/nestjs-auth-module';
import { UserRepositoryService } from './user-repository.service';
import { RefreshTokenRepositoryService } from './refresh-token-repository.service';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),

    AuthModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        jwt: {
          accessToken: createSymmetricTokenConfig({
            secret: config.get('JWT_SECRET')!,
            signOptions: {
              expiresIn: '15m',
              algorithm: 'HS256',
            },
          }),
          refreshToken: {
            expiresIn: 7 * 24 * 60 * 60, // 7 days in seconds
          },
        },
        credentials: {},
        google: {
          clientID: config.get('GOOGLE_CLIENT_ID')!,
          clientSecret: config.get('GOOGLE_CLIENT_SECRET')!,
          callbackURL: config.get('GOOGLE_CALLBACK_URL')!,
        },
      }),
      userRepository: UserRepositoryService,
      refreshTokenRepository: RefreshTokenRepositoryService, // Optional
      enabledCapabilities: ['credentials', 'google'],
    }),
  ],
  providers: [
    UserRepositoryService,
    RefreshTokenRepositoryService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
  controllers: [AuthController],
})
export class AppModule {}
```

---

## 🎯 Core Concepts

### Authentication vs Authorization

This module provides authentication only (verifying user identity). For authorization (checking permissions), implement your own guards and decorators based on your business logic.

### Capabilities

Enable only what you need:

```ts
enabledCapabilities: ['credentials'];
// or
enabledCapabilities: ['google'];
// or
enabledCapabilities: ['credentials', 'google'];
```

### Refresh Tokens

Refresh tokens are optional. To enable them:

1. Implement the `RefreshTokenRepository` interface
2. Pass `refreshTokenRepository` to `AuthModule.forRootAsync()`
3. Configure `refreshToken` settings in your JWT config

Refresh tokens use SHA-256 hashing and implement a one-time use pattern for enhanced security.

---

## 🔧 Configuration

### JWT Configuration

```ts
import {
  createSymmetricTokenConfig,
  createAsymmetricTokenConfig,
} from '@nahnah/nestjs-auth-module';
import * as fs from 'fs';

const isProd = process.env.NODE_ENV === 'production';

const accessToken = isProd
  ? createAsymmetricTokenConfig({
      publicKey: fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH!),
      privateKey: fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH!),
      signOptions: {
        expiresIn: '15m',
        algorithm: 'RS256',
        issuer: 'my-app',
      },
    })
  : createSymmetricTokenConfig({
      secret: process.env.JWT_SECRET!,
      signOptions: {
        expiresIn: '15m',
        algorithm: 'HS256',
        issuer: 'my-app',
      },
    });
```

### Google OAuth Configuration

```ts
google: {
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/callback',
  scope: ['email', 'profile'], // Optional, defaults to ['email', 'profile']
}
```

---

## 📚 User Repository Contract

### Basic User Repository

```ts
interface UserRepository<User extends Partial<AuthUser>> {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(data: Partial<User>): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
}
```

### Google User Repository (extends UserRepository)

```ts
interface GoogleUserRepository<
  User extends Partial<AuthUser>,
> extends UserRepository<User> {
  findByGoogleId(googleId: string): Promise<User | null>;
}
```

### Refresh Token Repository

```ts
interface RefreshTokenRepository<RT extends BaseRefreshTokenEntity> {
  create(data: Omit<RT, 'id'>): Promise<RT>;
  findByTokenHash(token: string): Promise<RT | null>;
  delete(id: string): Promise<void>;
  deleteAllForUser(userId: string): Promise<void>;
  deleteExpired?(): Promise<void>; // Optional cleanup method
}
```

---

## 🎨 Decorators

### `@Public()`

Skip authentication for a route:

```ts
@Public()
@Get('health')
getHealth() {
  return { status: 'ok' };
}
```

### `@CurrentUser()`

Access the authenticated user:

```ts
// Get entire user object
@Get('profile')
getProfile(@CurrentUser() user: RequestUser) {
  return user;
}

// Get specific field
@Get('id')
getUserId(@CurrentUser('userId') userId: string) {
  return { userId };
}
```

---

## 🛡️ Services

### CredentialsAuthService

Handles email/password authentication:

```ts
// Register new user
await credentialsAuth.register({ email, password });

// Login
await credentialsAuth.login({ email, password });

// Change password (requires current password)
await credentialsAuth.changePassword({ userId, currentPassword, newPassword });

// Set/reset password (admin operation)
await credentialsAuth.setPassword({ userId, newPassword });

// Verify email
await credentialsAuth.verifyEmail(userId);

// Validate user exists
await credentialsAuth.validateUser(userId);
```

### GoogleAuthService

Handles Google OAuth authentication:

```ts
// Complete OAuth callback
await googleAuth.handleOAuthCallback(requestUser);

// Unlink Google account
await googleAuth.unlinkGoogleAccount(userId);

// Check if Google is linked
const isLinked = await googleAuth.isGoogleLinked(userId);
```

### AuthJwtService

Manages JWT tokens:

```ts
// Generate access token only
const accessToken = authJwt.generateAccessToken(userId);

// Generate both tokens (if refresh enabled)
const { accessToken, refreshToken } = await authJwt.generateTokens(userId);

// Refresh tokens
const newTokens = await authJwt.refreshTokens(oldRefreshToken);

// Revoke specific token
await authJwt.revokeToken(tokenId);

// Revoke all tokens (logout all devices)
await authJwt.revokeAllTokens(userId);
```

---

## 🔐 Security Best Practices

- Always use **environment variables** for secrets
- Enforce **HTTPS** in production
- Use **asymmetric keys** (RS256) for enhanced security
- Implement **rate limiting** on auth endpoints
- Enforce **strong password policies**
- Set appropriate **token expiration times** (15m for access, 7d for refresh)
- Store refresh tokens securely with **SHA-256 hashing**
- Implement **refresh token rotation** (one-time use pattern included)
- Add **CSRF protection** for cookie-based implementations

---

## 🔄 Token Refresh Flow

1. User logs in and receives access + refresh tokens
2. Access token expires after 15 minutes
3. Client sends refresh token to `/auth/refresh` endpoint
4. Module validates refresh token and deletes it (one-time use)
5. Module generates new access + refresh token pair
6. Old refresh token is invalidated

---

## 🗺️ Roadmap

- [x] Refresh token rotation & one-time use
- [ ] Magic link authentication
- [ ] Account lockout after failed attempts
- [ ] Password reset flow helpers
- [ ] Email verification flow helpers
- [ ] More OAuth providers (GitHub, Microsoft, etc.)
- [ ] Redis adapter for refresh tokens
- [ ] Token blacklisting for access tokens

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🪪 License

MIT — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Built with [NestJS](https://nestjs.com/)
- Uses [Passport](http://www.passportjs.org/) for authentication strategies
- Password hashing with [Argon2](https://github.com/ranisalt/node-argon2)

---

## 💬 Support

- 🐛 [Report Issues](https://github.com/tgenericx/nestjs-auth-module/issues)
- 💡 [Request Features](https://github.com/tgenericx/nestjs-auth-module/issues/new)
- ⭐ Star the repo if it helped you!
