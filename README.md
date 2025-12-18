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

It provides JWT-based authentication with access and refresh tokens, secure password hashing via **Argon2**, optional **Google OAuth**, role-based authorization, and a clean **interface-driven architecture** that lets you bring your own database and email implementation.

If you want **speed without sacrificing structure**, this module is for you.

---

## ✨ Features

- 🔐 **JWT Authentication** — Access & refresh tokens with configurable lifetimes
- 🔑 **Secure Passwords** — Argon2 hashing out of the box
- 🌐 **Google OAuth 2.0** — Optional social authentication
- 👥 **Role-Based Access Control** — `@Roles()` decorator + guard
- 🎯 **Clean DX** — `@Public()`, `@CurrentUser()` decorators
- 🔌 **Database-Agnostic** — Bring your own repository
- 📦 **Capability-Driven** — Enable only what you need
- 🛡️ **Fully Type-Safe** — Strict TypeScript support
- ⚡ **Sensible Defaults** — Zero-config to get started fast

---

## 📦 Installation

```bash
npm install @nahnah/nestjs-auth-module
# or
yarn add @nahnah/nestjs-auth-module
# or
pnpm add @nahnah/nestjs-auth-module
```

### Required Peer Dependencies

```bash
npm install @nestjs/common @nestjs/core @nestjs/jwt @nestjs/passport \
passport passport-jwt argon2 class-validator class-transformer
```

### Optional (Google OAuth)

```bash
npm install passport-google-oauth20 @types/passport-google-oauth20
```

---

## 🚀 Quick Start

### 1️⃣ Implement a User Repository

The module is **database-agnostic**. You must implement the `UserRepository` interface.

```ts
import { Injectable } from '@nestjs/common';
import { UserRepository, AuthUser } from '@nahnah/nestjs-auth-module';

export interface User extends AuthUser {
  firstName?: string;
  lastName?: string;
  createdAt?: Date;
}

@Injectable()
export class UserRepositoryService implements UserRepository<User> {
  private users = new Map<string, User>();

  async findById(id: string) {
    return this.users.get(id) ?? null;
  }

  async findByEmail(email: string) {
    return [...this.users.values()].find(u => u.email === email) ?? null;
  }

  async findByGoogleId(googleId: string) {
    return [...this.users.values()].find(u => u.googleId === googleId) ?? null;
  }

  async create(data: Partial<User>) {
    const user: User = {
      id: crypto.randomUUID(),
      email: data.email!,
      password: data.password ?? null,
      googleId: data.googleId ?? null,
      isEmailVerified: data.isEmailVerified ?? false,
      roles: data.roles ?? ['user'],
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

---

### 2️⃣ Configure the Auth Module

```ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from '@nahnah/nestjs-auth-module';
import { UserRepositoryService } from './users/user-repository.service';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),

    AuthModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        jwt: {
          accessTokenSignOptions: {
            secret: config.get('JWT_SECRET')!,
            expiresIn: '15m',
          },
          refreshTokenSignOptions: {
            secret: config.get('JWT_REFRESH_SECRET')!,
            expiresIn: '7d',
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
      enabledCapabilities: ['credentials', 'google'],
    }),
  ],
  providers: [UserRepositoryService],
})
export class AppModule {}
```

---

## 🎯 Core Concepts

### Capabilities

Enable only what you need:

```ts
enabledCapabilities: ['credentials'];
// or
enabledCapabilities: ['google'];
// or
enabledCapabilities: ['credentials', 'google'];
```

---

### User Repository Contract

```ts
interface UserRepository<User extends Partial<AuthUser>> {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(data: Partial<User>): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
}
```

---

## 🎨 Decorators

### `@Public()`

Skip authentication for a route.

### `@CurrentUser()`

Access the authenticated user or a specific field.

### `@Roles()`

Restrict access by role (use with `RolesGuard`).

---

## 🔐 Security Best Practices

- Always use **environment variables** for secrets
- Enforce **HTTPS** in production
- Implement **refresh token rotation** (roadmap)
- Add **rate limiting** to auth endpoints
- Enforce **strong password policies**

---

## 🗺️ Roadmap

- [ ] Refresh token rotation & blacklisting
- [ ] Magic link authentication
- [ ] Account lockout after failed attempts
- [ ] Password reset flow helpers
- [ ] Email verification flow helpers
- [ ] More OAuth providers (GitHub, Microsoft, etc.)

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
