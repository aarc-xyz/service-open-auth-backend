import { Injectable, Logger } from '@nestjs/common';
import { AuthMethodType } from '@lit-protocol/constants';
import { GoogleAuthProvider } from '../authProviders/Google.authProvider';
import { AuthMethodResponseObject, Provider } from '../common/types';
import { ServiceError } from '../common/types';
import { GetPubKeyDto } from '../dto/Accounts.dto';
import { OAuthClientDataRepository } from "../repositories/oAuthClientData.repository";

@Injectable()
export class NativeAuthClient {
  private readonly logger: Logger = new Logger(NativeAuthClient.name);
  constructor(
    private readonly oauthClientDataRepository: OAuthClientDataRepository,
    private readonly googleAuthProvider: GoogleAuthProvider
  ) {}

  async hasNativeAuthEnabled(
    apiKeyHash: string,
    provider: Provider,
  ): Promise<boolean> {
    try {
      const client = await this.oauthClientDataRepository.findOneByKey(
        apiKeyHash,
        provider,
      );
      if (!client) {
        return false;
      }
      return true;
    } catch (error) {
      this.logger.error(
        `Error fetching client data for provider ${provider}`,
        error,
      );
      throw new ServiceError(
        `Error fetching client data for provider ${provider}`,
        error,
      );
    }
  }

  async registerCredentials(
    provider: Provider,
    apiKeyHash: string,
    credentials: Record<string, unknown>,
  ): Promise<void> {
    try {
      switch (provider) {
        case Provider.GOOGLE: {
          const clientId = credentials['client_id'] as string;
          const clientSecret = credentials['client_secret'] as string;

          if (!clientId || clientId === '') {
            throw new ServiceError('Invalid clientId');
          }

          if (!clientSecret || clientSecret === '') {
            throw new ServiceError('Invalid clientSecret');
          }

          await this.googleAuthProvider.registerCredentials(
            apiKeyHash,
            clientId,
            clientSecret,
          );
          return;
        }
        default: {
          throw new ServiceError(
            'Invalid Provider or this provider is not supported',
          );
        }
      }
    } catch (error) {
      this.logger.log(
        `Error registering credentials for provider ${provider}`,
        error,
      );
      throw new ServiceError(
        `Error registering credentials for provider ${provider}`,
        error,
      );
    }
  }

  async getCallbackUrl(
    provider: Provider,
    apiKeyHash: string,
    state?: string,
  ): Promise<{
    hasNativeAuth: boolean;
    callbackUrl: string;
  }> {
    try {
      const hasNativeAuth = await this.hasNativeAuthEnabled(
        apiKeyHash,
        provider,
      );
      if (!hasNativeAuth) {
        return {
          hasNativeAuth: false,
          callbackUrl: '',
        };
      }

      switch (provider) {
        case Provider.GOOGLE: {
          const callbackUrl = await this.googleAuthProvider.generateCallbackUrl(
            apiKeyHash,
          );
          if (!callbackUrl || callbackUrl === '') {
            throw new ServiceError('Error generating callback url');
          }

          this.logger.debug(
            `Generated callback url for provider ${provider}: ${callbackUrl}`,
          );
          return {
            hasNativeAuth: true,
            callbackUrl,
          };
        }
        default: {
          throw new ServiceError(
            'Invalid Provider or this provider is not supported',
          );
        }
      }
    } catch (error) {
      this.logger.error(
        `Error generating callback url for provider ${provider}`,
        error,
      );
      throw new ServiceError(
        `Error generating callback url for provider ${provider}`,
        error,
      );
    }
  }

  async verifyRequest(
    provider: Provider,
    apiKey: string,
    params: GetPubKeyDto,
  ): Promise<AuthMethodResponseObject> {
    try {
      switch (provider) {
        case Provider.GOOGLE: {
          const oauth_token = params.authKey;
          if (!oauth_token) {
            throw new ServiceError('Invalid request');
          }

          const response = await this.googleAuthProvider.verify(oauth_token);
          if (!response) {
            throw new ServiceError('Failed to authenticate request');
          }

          return {
            authMethod: {
              authMethodType: AuthMethodType.Google,
              accessToken: oauth_token,
            },
            authId: apiKey,
            primary_contact: response.email,
            profile_picture_url: response.profile_pic,
            user: {
              first_name: response.first_name,
              last_name: response.last_name,
              primary_contact: response.email,
              profile_picture_url: response.profile_pic,
            },
          };
        }
        default: {
          throw new ServiceError(
            'Invalid Provider or this provider is not supported',
          );
        }
      }
    } catch (error) {
      this.logger.error(
        `Error verifying request for provider ${provider}`,
        error,
      );
      throw new ServiceError(
        `Error verifying request for provider ${provider}`,
        error,
      );
    }
  }
}
