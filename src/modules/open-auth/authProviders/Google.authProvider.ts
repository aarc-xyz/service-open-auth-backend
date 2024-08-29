import { Injectable } from '@nestjs/common';
import { BaseAuthProvider } from './Base.authProvider';
import { Provider } from '../common/types';
import { OAuthClientDataRepository } from '../repositories/oAuthClientData.repository';
import { ServiceError } from '../common/types';
import {
  PLATFORM_CALLBACK_URL,
  GOOGLE_OAUTH_SIGNIN_ENDPOINT,
  GOOGLE_OAUTH_VERIFY_ENDPOINT,
  GOOGLE_REVOKE_TOKEN_ENDPOINT,
} from '../common/constants';
import { Mixed } from 'mongoose';
import { decryptData } from '../common/helpers';

@Injectable()
export class GoogleAuthProvider extends BaseAuthProvider {
  constructor(
    private readonly oAuthClientDataRepository: OAuthClientDataRepository,
  ) {
    super(Provider.GOOGLE, GoogleAuthProvider.name);
  }

  async registerCredentials(
    id: string,
    clientId: string,
    clientSecret: string,
  ): Promise<void> {
    try {
      await this.oAuthClientDataRepository.addOrUpdateClientData({
        clientId: id,
        provider: Provider.GOOGLE,
        credentials: {
          clientId: clientId as unknown as Mixed,
          clientSecret: clientSecret as unknown as Mixed,
        },
      });
    } catch (error) {
      this.logger.error('Error registering credentials', error);
      this.logger.error(error);
      throw new ServiceError('Error registering credentials', error);
    }
  }

  async generateCallbackUrl(id: string, state?: string): Promise<string> {
    try {
      const clientData = await this.oAuthClientDataRepository.findOneByKey(
        id,
        Provider.GOOGLE,
      );
      if (!clientData) {
        this.logger.error('Client data not found');
        throw new ServiceError('Client data not found');
      }

      const googleOAuthEndpoint: string = GOOGLE_OAUTH_SIGNIN_ENDPOINT;
      const encryptedClientId: string = clientData.credentials[
        'clientId'
        ] as unknown as string;
      if (!encryptedClientId) {
        this.logger.error('Client not registered, google client ID not found');
        throw new ServiceError(
          'Client not registered, google client ID not found',
        );
      }
      const clientId = decryptData(encryptedClientId);
      const redirectUri: string = encodeURIComponent(`${PLATFORM_CALLBACK_URL}`);
      const scope: string = encodeURIComponent('email profile openid');
      const responseType = 'token';
      const includeGrantedScopes = true;
      const callbackState = state ? `&state=${state}` : '';

      return `${googleOAuthEndpoint}?client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}&include_granted_scopes=${includeGrantedScopes}` + callbackState;
    } catch (error) {
      this.logger.error('Error generating callback url', error);
      throw new ServiceError('Error generating callback url', error);
    }
  }

  async verify(oauth_token: string): Promise<{
    email: string;
    profile_pic?: string;
    first_name?: string;
    last_name?: string;
  }> {
    try {
      const response = await fetch(GOOGLE_OAUTH_VERIFY_ENDPOINT, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${oauth_token}`,
        },
      });
      if (!response.ok) {
        const error = await response.json();
        this.logger.error('Error verifying google access token', error);
        throw new ServiceError('Error verifying google access token', error);
      }

      const tokenInfo = await response.json();
      this.logger.debug('Token info', tokenInfo);

      // revoke token
      fetch(GOOGLE_REVOKE_TOKEN_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `token=${oauth_token}`,
      }).catch((error) => {
        this.logger.log(
          'Failed to revoke token for google email',
          tokenInfo.email,
          error,
        );
      });

      const email = tokenInfo.email;
      const profile_pic = tokenInfo.picture;
      const first_name = tokenInfo.given_name;
      const last_name = tokenInfo.family_name;

      return {
        email,
        profile_pic,
        first_name,
        last_name,
      };
    } catch (error) {
      this.logger.error('Error verifying token', error);
      throw new ServiceError('Error verifying token', error);
    }
  }
}
