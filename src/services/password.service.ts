import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import { IPasswordConfig } from 'src/interfaces/auth-config.interface';

@Injectable()
export class PasswordService {
  async hash(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id, // Most secure variant
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }

  async compare(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      return false;
    }
  }

  generateResetToken(): string {
    return randomBytes(32).toString('hex');
  }

  validate(password: string, config?: IPasswordConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (config?.minLength && password.length < config.minLength) {
      errors.push(`Password must be at least ${config.minLength} characters`);
    }

    if (config?.requireSpecialChar && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    if (config?.requireNumber && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (config?.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    return { valid: errors.length === 0, errors };
  }
}
