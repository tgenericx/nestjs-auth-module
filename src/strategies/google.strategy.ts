import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { AUTH_MODULE_CONFIG } from '../auth.constants';
import type { IAuthModuleConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(@Inject(AUTH_MODULE_CONFIG) config: IAuthModuleConfig) {
    if (!config.google?.clientID || !config.google?.clientSecret || !config.google?.callbackURL) {
      throw new Error('Google OAuth configuration is missing or incomplete.');
    }
    super({
      clientID: config.google.clientID,
      clientSecret: config.google.clientSecret,
      callbackURL: config.google.callbackURL,
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, emails, displayName, photos } = profile;

    const user = {
      googleId: id,
      email: emails[0].value,
      displayName,
      photo: photos[0]?.value,
      accessToken,
    };

    done(null, user);
  }
}
