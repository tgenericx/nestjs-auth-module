import { Injectable } from '@nestjs/common';
import { HashService } from '../utils/hash.service';

@Injectable()
export class PasswordService {
  constructor(private readonly hashService: HashService) {}

  async hash(password: string): Promise<string> {
    return this.hashService.hash(password);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    return this.hashService.verify(password, hash);
  }

  generateResetToken(): string {
    return this.hashService.generateSecureToken();
  }
}
