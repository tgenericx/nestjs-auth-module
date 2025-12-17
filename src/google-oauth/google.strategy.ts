import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import type {
  AuthUser,
  GoogleOAuthConfig,
  RequestUser,
  UserRepository,
} from '../interfaces';
import { AUTH_CAPABILITIES, PROVIDERS } from '../constants/tokens';

@Injectable()
export class GoogleStrategy<User extends AuthUser> extends PassportStrategy(
  Strategy,
  'google',
) {
  constructor(
    @Inject(AUTH_CAPABILITIES.GOOGLE)
    private readonly config: GoogleOAuthConfig | undefined,
    @Inject(PROVIDERS.USER_REPOSITORY)
    private readonly user: UserRepository<User>,
  ) {
    if (!config) {
      throw new Error(
        'GoogleOAuthModule is imported but Google config is not provided. ' +
          'Either remove the module or provide google config in AuthModule.forRootAsync()',
      );
    }
    super({
      ...config,
      scope: config.scope || ['email', 'profile'],
      passReqToCallback: config.passReqToCallback || false,
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, emails } = profile;
    const email = emails?.[0]?.value;

    if (!email) {
      return done(new Error('No email found in Google profile'));
    }

    let user: Pick<User, 'id' | 'roles'> | null =
      await this.user.findByGoogleId(id);

    if (!user) {
      user = await this.user.findByEmail(email);
      if (user) {
        user = await this.user.update(user.id, {
          googleId: id,
        } as Partial<User>);
      } else {
        user = await this.user.create({
          email,
          googleId: id,
          isEmailVerified: true,
        } as Partial<User>);
      }
    }
    const requestUser: RequestUser = {
      userId: user.id,
      roles: user.roles,
    };

    done(null, requestUser);
  }
}
