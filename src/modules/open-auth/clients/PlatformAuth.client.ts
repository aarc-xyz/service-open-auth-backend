import { BadRequestException, Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { AuthMethodResponseObject, Provider } from '../common/types';
import { ServiceError } from '../common/types';
import { GetPubKeyDto } from '../dto/Accounts.dto';
import { StytchClient } from "./Stytch.client";
import { FarcasterAuthProvider } from "../authProviders/Farcaster.authProvider";
import { TelegramAuthProvider } from "../authProviders/Telegram.authProvider";
import { TwitterAuthProvider } from "../authProviders/Twitter.authProvider";
import { WebAuthnProvider } from "../authProviders/Webauthn.authProvider";
import { LitClient } from "./Lit.client";
import { TwilioAuthProvider } from "../authProviders/Twilio.authProvider";
import { Request } from "express";
import { customAuthMethod } from "../common/helpers";
import { LIT_CUSTOM_AUTH_TYPE_ID } from "../common/constants";

@Injectable()
export class PlatformAuthClient {
  private readonly logger: Logger = new Logger(PlatformAuthClient.name);
  constructor(
    private readonly litClient: LitClient,
    private readonly stytchClient: StytchClient,
    private readonly twilioAuthProvider: TwilioAuthProvider,
    private readonly farcasterAuthProvider: FarcasterAuthProvider,
    private readonly telegramAuthProvider: TelegramAuthProvider,
    private readonly twitterAuthProvider: TwitterAuthProvider,
    private readonly webAuthnProvider: WebAuthnProvider
  ) {}

  async verifyRequest(apiKeyHash: string, provider: Provider, params: GetPubKeyDto, request: Request): Promise<AuthMethodResponseObject> {
    try {
      switch (provider) {
        case Provider.GOOGLE:
        case Provider.DISCORD: {
          const sessionResponse = await this.stytchClient.handleProviderOauth(
            params.authKey,
          );
          const authMethodResponse = await this.litClient.generateProviderAuthMethod(
            sessionResponse.session_jwt,
          );

          authMethodResponse['primary_contact'] =
            sessionResponse?.user?.emails[0]?.email;
          authMethodResponse['user'] = sessionResponse.user.name;
          for (const auth_provider of sessionResponse.user.providers) {
            if (auth_provider.provider_type.toLowerCase() == provider) {
              authMethodResponse['profile_picture_url'] =
                auth_provider?.profile_picture_url;
              break;
            }
          }
          return authMethodResponse;
        }
        case Provider.EMAIL: {
          if (!params.code) {
            throw new BadRequestException('Invalid request, Missing code');
          }

          if (!params.phone_number) {
            throw new BadRequestException('Invalid request, Missing phone_number');
          }

          const sessionResponse = await this.stytchClient.validateEmailOTP(
            params.code,
            params.method_id,
          );
          const authMethodResponse =
            await this.litClient.generateProviderAuthMethod(
              sessionResponse.session_jwt,
            );
          authMethodResponse['primary_contact'] =
            sessionResponse?.user?.emails[0]?.email;
          authMethodResponse['user'] = { ...sessionResponse?.user?.name };
          return authMethodResponse;
        }
        case Provider.SMS: {
          if (!params.code || !params.phone_number) {
            throw new BadRequestException('Invalid request');
          }
          const success = this.twilioAuthProvider.verifyPasscode(
            params.phone_number,
            params.code,
          );
          if (!success) {
            throw new BadRequestException('Invalid request, Authentication failed');
          }

          const customAuth = customAuthMethod(params.phone_number);
          return {
            authMethod: {
              authMethodType: LIT_CUSTOM_AUTH_TYPE_ID,
              accessToken: null,
            },
            authId: customAuth.id,
            primary_contact: params.phone_number,
            user: {
              primary_contact: params.phone_number,
            },
          };
        }
        case Provider.TELEGRAM: {
          if (!params.telegram_session) {
            throw new ServiceError('Telegram auth data not passed');
          }
          if (
            !params.telegram_session.id ||
            !params.telegram_session.hash ||
            !params.telegram_session.auth_date
          ) {
            throw new ServiceError(
              'Missing required parameters for Telegram auth, missing id or hash or aut_date',
            );
          }

          const telegramSession = params.telegram_session;
          const authMethodResponse = await this.telegramAuthProvider.verify(telegramSession);

          if (telegramSession.photo_url) {
            authMethodResponse.profile_picture_url =
              telegramSession.photo_url;
            authMethodResponse.user = {
              profile_picture_url: telegramSession.photo_url,
            };
          }

          if (telegramSession.first_name) {
            authMethodResponse.user = {
              ...authMethodResponse.user,
              first_name: telegramSession.first_name,
            };
          }

          if (telegramSession.last_name) {
            authMethodResponse.user = {
              ...authMethodResponse.user,
              last_name: telegramSession.last_name,
            };
          }

          if (telegramSession.username) {
            authMethodResponse.user = {
              ...authMethodResponse.user,
              username: telegramSession.username,
            };
          }
          return authMethodResponse;
        }
        case Provider.FARCASTER: {
          if (!params.farcaster_session) {
            throw new ServiceError('Farcaster auth data not passed');
          }

          const farcasterSession = params.farcaster_session;
          const sessionResponse = await this.farcasterAuthProvider.verify(farcasterSession);
          if (!sessionResponse.success || !sessionResponse.fid) {
            throw new UnauthorizedException('Failed to authenticate farcaster request');
          }

          const customAuth = customAuthMethod(sessionResponse.fid);
          return {
            authMethod: {
              authMethodType: LIT_CUSTOM_AUTH_TYPE_ID,
              accessToken: null,
            },
            authId: customAuth.id,
            primary_contact: sessionResponse.fid,
          };
        }
        case Provider.X: {
          const xAuthSession = params.x_session;
          if (!xAuthSession) {
            throw new BadRequestException(
              'X authentication failed: X Auth data not passed',
            );
          }

          if (!xAuthSession.oauth_token) {
            throw new BadRequestException(
              'X authentication failed: X Auth token not passed',
            );
          }

          if (!xAuthSession.oauth_verifier) {
            throw new BadRequestException(
              'X authentication failed: X Auth verifier not passed',
            );
          }

         return this.twitterAuthProvider.verify(apiKeyHash, xAuthSession);
        }
        case Provider.WEBAUTHN: {
          const webAuthnData = params.webauthn_session;
          if (!webAuthnData) {
            throw new ServiceError('Webauthn data not passed');
          }

          const primary_contact =
            await this.webAuthnProvider.verify(
              request.headers.origin,
              webAuthnData,
            );
          if (!primary_contact) {
            throw new ServiceError('Webauthn authentication failed');
          }

          const customAuth = customAuthMethod(primary_contact);
          return {
            primary_contact,
            authMethod: {
              authMethodType: customAuth.authMethodType,
              accessToken: null,
            },
            authId: customAuth.id,
          };
        }
        default: {
          this.logger.error(`Invalid Provider: ${provider}`);
          throw new ServiceError('Invalid Provider');
        }
      }
    } catch (error) {
      this.logger.error(`Error verifying provider: ${provider}`, error);
      throw new ServiceError(`Error verifying provider: ${provider}`, error);
    }
  }
}
