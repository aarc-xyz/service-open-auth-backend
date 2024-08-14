import { Injectable, Logger } from '@nestjs/common';
import { AuthMethodResponseObject, Provider, ServiceError } from "../common/types";
import {
  X_API_BASE_URL,
  X_OAUTH_CALLBACK,
  X_OAUTH_VERSION,
  X_OAUTH_CONSUMER_KEY,
  X_OAUTH_CONSUMER_SECRET,
  X_OAUTH_SIGNATURE_METHOD, LIT_CUSTOM_AUTH_TYPE_ID
} from "../common/constants";
import * as crypto from 'node:crypto';
import * as qs from 'querystring';
import { ethers } from 'ethers';
import {
  customAuthMethod, decryptData,
  generateHamcSignature
} from "../common/helpers";
import { TokenAndSecretRepository } from '../repositories/tokenAndSecret.repository';
import { BaseAuthProvider } from "./Base.authProvider";
import { OAuthClientDataRepository } from "../repositories/oAuthClientData.repository";
import { Mixed } from "mongoose";
import { XClientSecrets } from "../dto/AuthProviders.dto";
import { XAuthDto } from "../dto/Accounts.dto";

@Injectable()
export class TwitterAuthProvider extends BaseAuthProvider {
  constructor(
    private readonly tokenAndSecretRepository: TokenAndSecretRepository,
    private readonly oauthClientDataRepository: OAuthClientDataRepository,
  ) {
    super(Provider.X, TwitterAuthProvider.name);
    this.logger.log('Twitter authProviders initialized');
  }

  async registerCredentials(
    apiKeyHash: string,
    consumerKey: string,
    consumerSecret: string,
    oauthCallBack: string,
  ): Promise<void> {
    try {
      await this.oauthClientDataRepository.addOrUpdateClientData({
        apiKeyHash: apiKeyHash,
        provider: Provider.X,
        credentials: {
          consumerKey: consumerKey as unknown as Mixed,
          consumerSecret: consumerSecret as unknown as Mixed,
          oauthCallBack: oauthCallBack as unknown as Mixed,
        },
      });
    } catch (error) {
      this.logger.error('Error registering credentials', error);
      throw new ServiceError('Error registering credentials', error);
    }
  }

  async generateCallbackUrl(apiKeyHash: string, state?: string): Promise<string> {
    try {
      const clientData = await this.oauthClientDataRepository.findOneByKey(
        apiKeyHash,
        Provider.X,
      );

      if (!clientData) {
        this.logger.error('Client data not found');
        throw new ServiceError('Client data not found');
      }

      const consumerKey: string = clientData.credentials['consumerKey'] as unknown as string;
      const consumerSecret: string = clientData.credentials['consumerSecret'] as unknown as string;
      const oauthCallBack: string = clientData.credentials['oauthCallBack'] as unknown as string;

      if (!consumerKey || !consumerSecret || !oauthCallBack) {
        this.logger.error('Client not registered, consumer key or consumer secret not found');
        throw new ServiceError('Client not registered, consumer key or consumer secret not found');
      }

      const requestToken = await this.generateRequestToken(state, {
        consumerKey,
        consumerSecret,
        oauthCallback: oauthCallBack,
      });

      return `${X_API_BASE_URL}/oauth/authenticate?oauth_token=${requestToken}`;
    } catch (error) {
      this.logger.error('Error generating callback URL', error);
      throw new ServiceError('Error generating callback URL', error);
    }
  }

  async verify(apiKeyHash: string, xAuthData: XAuthDto): Promise<AuthMethodResponseObject> {
    try {
      const tokenAndSecret = await this.tokenAndSecretRepository.findOneByKey(
        xAuthData.oauth_token,
      );

      if (!tokenAndSecret) {
        throw new ServiceError('Token data not found for the request');
      }

      const xClientSecrets = await this.oauthClientDataRepository.findOneByKey(
        apiKeyHash,
        Provider.X,
      );

      const encryptedXClientKey = xClientSecrets.credentials['consumerKey'] as unknown as string;
      const encryptedXClientSecret = xClientSecrets.credentials['consumerSecret'] as unknown as string;
      const encryptedXOAuthCallBack = xClientSecrets.credentials['oauthCallBack'] as unknown as string;

      const xClientKey = decryptData(encryptedXClientKey);
      const xClientSecret = decryptData(encryptedXClientSecret);
      const xOAuthCallBack = decryptData(encryptedXOAuthCallBack);

      const accessToken = await this.generateAccessToken(
        xAuthData.oauth_token,
        xAuthData.oauth_verifier,
        {
          consumerKey: xClientKey,
          consumerSecret: xClientSecret,
          oauthCallback: xOAuthCallBack,
        }
      );

      const authHeader = this.generateXAuthHeader(
        accessToken.oauth_token,
        accessToken.oauth_token_secret,
        'GET',
        {},
        {
          consumerKey: xClientKey,
          consumerSecret: xClientSecret,
          oauthCallback: xOAuthCallBack,
        }
      );

      const credentials = await this.getTwitterAccountCredentials(authHeader);
      const customAuth = customAuthMethod(credentials.email);

      return {
        authMethod: {
          authMethodType: LIT_CUSTOM_AUTH_TYPE_ID,
          accessToken: null,
        },
        authId: customAuth.id,
        primary_contact: credentials.email,
        profile_picture_url: credentials.profile_picture_url,
        user: {
          first_name: credentials.name,
          primary_contact: credentials.email,
          profile_picture_url: credentials.profile_picture_url,
        }
      }

    } catch (error) {
      this.logger.error('Error verifying X authentication', error);
      throw new ServiceError('Error verifying X authentication', error);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  get xOAuthParams(): any {
    return {
      oauth_consumer_key: X_OAUTH_CONSUMER_KEY,
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: X_OAUTH_SIGNATURE_METHOD,
      oauth_timestamp: Math.floor(Date.now() / 1000),
      oauth_version: X_OAUTH_VERSION,
    };
  }

  async generateRequestToken(
    state: string,
    xClientSecrets?: XClientSecrets
  ): Promise<string> {
    const callbackUrl = `${xClientSecrets.oauthCallback || X_OAUTH_CALLBACK}?state=${state}`;
    const params = { oauth_callback: callbackUrl, ...this.xOAuthParams };

    const baseString =
      'POST&' +
      encodeURIComponent(`${X_API_BASE_URL}/oauth/request_token`) +
      '&' +
      encodeURIComponent(qs.stringify(params));
    const signingKey = encodeURIComponent(xClientSecrets.consumerSecret || X_OAUTH_CONSUMER_SECRET) + '&';
    const oauthSignature = generateHamcSignature(signingKey, baseString);

    const authorizationHeader = `OAuth oauth_nonce="${
      params.oauth_nonce
    }", oauth_callback="${encodeURIComponent(
      callbackUrl,
    )}", oauth_signature_method="${
      params.oauth_signature_method
    }", oauth_timestamp="${
      params.oauth_timestamp
    }", oauth_consumer_key="${xClientSecrets.consumerKey || X_OAUTH_CONSUMER_KEY}", oauth_signature="${encodeURIComponent(
      oauthSignature,
    )}", oauth_version="${params.oauth_version}"`;

    try {
      const response = await fetch(`${X_API_BASE_URL}/oauth/request_token`, {
        method: 'POST',
        headers: {
          Authorization: authorizationHeader,
        },
      });

      if (!response.ok) {
        const error = await response.text();
        this.logger.error('Failed to generate request token', error);
        throw new ServiceError('Request to generate request token failed');
      }

      const data = await response.text();
      if (!data) {
        throw new ServiceError('Failed to get response from Twitter API');
      }

      const tokenData = qs.parse(data);

      await this.tokenAndSecretRepository.addTokenAndSecret(
        tokenData.oauth_token.toString(),
        tokenData.oauth_token_secret.toString(),
      );

      return tokenData.oauth_token.toString();
    } catch (error) {
      this.logger.error('Failed to generate request token', error);
      throw new ServiceError('Failed to generate request token');
    }
  }

  async generateAccessToken(
    oauthToken: string,
    oauthVerifier: string,
    xClientSecrets?: XClientSecrets
  ): Promise<{
    oauth_token: string;
    oauth_token_secret: string;
    user_id: string;
    screen_name: string;
  }> {
    const params = this.xOAuthParams;
    const tokenAndSecret = await this.tokenAndSecretRepository.findOneByKey(
      oauthToken,
    );

    if (!tokenAndSecret) {
      throw new ServiceError('Token data not found for the request');
    }

    const oauthTokenSecret = tokenAndSecret.secret;

    const baseString =
      'POST&' +
      encodeURIComponent(`${X_API_BASE_URL}/oauth/request_token`) +
      '&' +
      encodeURIComponent(qs.stringify(params));
    const signingKey =
      encodeURIComponent(xClientSecrets.consumerSecret || X_OAUTH_CONSUMER_SECRET) +
      '&' +
      encodeURIComponent(oauthTokenSecret);
    const oauthSignature = generateHamcSignature(signingKey, baseString);

    const authorizationHeader = `OAuth oauth_consumer_key="${xClientSecrets.consumerKey || X_OAUTH_CONSUMER_KEY}", oauth_nonce="${
      params.oauth_nonce
    }", oauth_signature="${encodeURIComponent(
      oauthSignature,
    )}", oauth_signature_method="${
      params.oauth_signature_method
    }", oauth_timestamp="${
      params.oauth_timestamp
    }", oauth_token="${oauthToken}", oauth_version="${params.oauth_version}"`;

    const requestBody = qs.stringify({ oauth_verifier: oauthVerifier });

    try {
      const response = await fetch(`${X_API_BASE_URL}/oauth/access_token`, {
        method: 'POST',
        body: requestBody,
        headers: {
          'User-Agent': "themattharris' HTTP Client",
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(requestBody).toString(),
          Authorization: authorizationHeader,
        },
      });

      if (!response.ok) {
        throw new ServiceError('Request to generate access token failed');
      }

      const data = await response.text();
      if (!data) {
        throw new ServiceError('Failed to get response from the Twitter API');
      }

      const tokenData = qs.parse(data);
      return {
        oauth_token: tokenData.oauth_token.toString(),
        oauth_token_secret: tokenData.oauth_token_secret.toString(),
        user_id: tokenData.user_id.toString(),
        screen_name: tokenData.screen_name.toString(),
      };
    } catch (error) {
      this.logger.error('Failed to generate access token', error);
      throw new ServiceError('Failed to generate access token');
    }
  }

  async getTwitterAccountCredentials(authHeader: string): Promise<{
    email: string;
    profile_picture_url: string;
    name: string;
  }> {
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: authHeader,
    };
    const credentials = await fetch(
      `${X_API_BASE_URL}/1.1/account/verify_credentials.json?include_email=true`,
      {
        method: 'GET',
        headers: headers,
      },
    );
    if (!credentials.ok) {
      throw new ServiceError('Failed to get Twitter account credentials');
    }

    const result = await credentials.json();
    if (result.email) {
      const customAuth = customAuthMethod(result.email);
      return {
        email: result.email,
        profile_picture_url: result.profile_image_url_https,
        name: result.name,
      };
    } else {
      throw new ServiceError('X authentication failed');
    }
  }

  generateXAuthHeader(
    xauth_token: string,
    xauth_secret: string,
    method: string,
    params = {}, // query params from twitter
    xClientSecrets?: XClientSecrets
  ): string {
    try {
      const headerParams = {
        oauth_consumer_key: xClientSecrets.consumerKey || X_OAUTH_CONSUMER_KEY,
        oauth_nonce: btoa(ethers.utils.id(`${Math.random}`)),
        oauth_signature_method: X_OAUTH_SIGNATURE_METHOD,
        oauth_timestamp: Date.now() / 1000,
        oauth_token: xauth_token,
        oauth_version: X_OAUTH_VERSION,
      };

      const signatureParams = { ...params, ...headerParams };

      const keys = Object.keys(signatureParams);
      let encodedSigKeys = [];
      const encodedSigParams = {};
      keys.forEach((key: string, index: number) => {
        const encodedKey = encodeURIComponent(key);
        const encodedValue = encodeURIComponent(signatureParams[key]);
        encodedSigParams[encodedKey] = encodedValue;
        encodedSigKeys.push(encodedKey);
      });
      encodedSigKeys = encodedSigKeys.sort();

      let encodedParamStr = '';
      encodedSigKeys.forEach((encodedKey, index) => {
        encodedParamStr =
          encodedParamStr + `${encodedKey}=${encodedSigParams[encodedKey]}&`;
      });
      encodedParamStr = encodedParamStr.slice(0, -1);

      const baseUrl = `${X_API_BASE_URL}/1.1/account/verify_credentials.json`;
      const signature_base_string =
        method +
        `&${encodeURIComponent(baseUrl)}&${encodeURIComponent(
          encodedParamStr,
        )}`;

      const signing_key = `${encodeURIComponent(
        xClientSecrets.consumerSecret || X_OAUTH_CONSUMER_SECRET,
      )}&${xauth_secret}`;

      const signature: string = generateHamcSignature(
        signing_key,
        signature_base_string,
      );

      headerParams[encodeURIComponent('oauth_signature')] =
        encodeURIComponent(signature);
      const headerKeys = Object.keys(headerParams).sort();
      let auth = 'OAuth ';
      headerKeys.forEach((encodedKey: string, index: number) => {
        auth = auth + `${encodedKey}="${headerParams[encodedKey]}", `;
      });
      auth = auth.slice(0, -2);

      Logger.log('header string ', auth);

      return auth;
    } catch (error) {
      Logger.error(error);
      throw new ServiceError('Authentication with X failed ', error);
    }
  }
}
