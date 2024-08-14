import { Injectable, Logger } from '@nestjs/common';
import stytch, {
  OAuthAuthenticateResponse,
  OTPsEmailLoginOrCreateResponse,
  SessionsAuthenticateResponse,
} from 'stytch';
import { ServiceError } from '../common/types';
import { STYTCH_PROJECT_ID, STYTCH_SECRET } from '../common/constants';

@Injectable()
export class StytchClient {
  private readonly logger = new Logger(StytchClient.name);
  private readonly stytchClient = new stytch.Client({
    project_id: STYTCH_PROJECT_ID,
    secret: STYTCH_SECRET,
  });

  async validateOAuth(token: string): Promise<OAuthAuthenticateResponse> {
    try {
      return await this.stytchClient.oauth.authenticate({
        token: token,
        session_duration_minutes: 60 * 24 * 7,
      });
    } catch (error) {
      throw new ServiceError('SessionAuthenticate Error', error);
    }
  }

  async handleProviderOauth(
    token: string,
  ): Promise<SessionsAuthenticateResponse> {
    try {
      const stytchResponse = await this.stytchClient.oauth.authenticate({
        token: token,
        session_duration_minutes: 60 * 24 * 7,
      });
      const sessionStatus = await this.stytchClient.sessions.authenticate({
        session_token: stytchResponse.session_token,
      });
      return sessionStatus;
    } catch (error) {
      throw new ServiceError('SessionAuthenticate Error', error);
    }
  }

  async sendPasscode(
    mode: string,
    user_contact: string,
  ): Promise<OTPsEmailLoginOrCreateResponse> {
    try {
      const stytchResponse: OTPsEmailLoginOrCreateResponse =
        await this.stytchClient.otps.email.loginOrCreate({
          email: user_contact,
        });
      this.logger.log(stytchResponse);
      return stytchResponse;
    } catch (error) {
      throw new ServiceError('Stytch OTP error', error);
    }
  }

  async validateEmailOTP(
    otp: string,
    method_id: string,
  ): Promise<SessionsAuthenticateResponse> {
    try {
      const authResponse = await this.stytchClient.otps.authenticate({
        method_id: method_id,
        code: otp,
        session_duration_minutes: 60 * 24 * 7,
      });

      this.logger.log(authResponse);

      const sessionStatus = await this.stytchClient.sessions.authenticate({
        session_token: authResponse.session_token,
      });

      this.logger.log(sessionStatus);
      return sessionStatus;
    } catch (error) {
      throw new ServiceError('Error in Validating OTP', error);
    }
  }
}
