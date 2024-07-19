import { Injectable, Logger } from '@nestjs/common';
import { ServiceError } from '../utils/types.interfaces';
import {
  X_API_BASE_URL,
  X_OAUTH_CALLBACK,
  X_OAUTH_VERSION,
  X_OAUTH_CONSUMER_KEY,
  X_OAUTH_CONSUMER_SECRET,
  X_OAUTH_SIGNATURE_METHOD,
} from '../utils/constants';
import * as crypto from 'node:crypto';
import * as qs from 'querystring';
import { ethers } from 'ethers';
import {
  customAuthMethod,
  generateHamcSignature,
} from '../utils/helper-functions';
import { TokenAndSecretRepository } from '../repositories/TokenAndSecret.repository';

@Injectable()
export class TwitterClient {
  private readonly logger: Logger = new Logger(TwitterClient.name);

  constructor(
    private readonly tokenAndSecretRepository: TokenAndSecretRepository,
  ) {
    this.logger.log('Twitter client initialized');
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

  async generateRequestToken(state: string): Promise<string> {
    const callbackUrl = `${X_OAUTH_CALLBACK}?state=${state}`;
    const params = { oauth_callback: callbackUrl, ...this.xOAuthParams };

    const baseString =
      'POST&' +
      encodeURIComponent(`${X_API_BASE_URL}/oauth/request_token`) +
      '&' +
      encodeURIComponent(qs.stringify(params));
    const signingKey = encodeURIComponent(X_OAUTH_CONSUMER_SECRET) + '&';
    const oauthSignature = generateHamcSignature(signingKey, baseString);

    const authorizationHeader = `OAuth oauth_nonce="${
      params.oauth_nonce
    }", oauth_callback="${encodeURIComponent(
      callbackUrl,
    )}", oauth_signature_method="${
      params.oauth_signature_method
    }", oauth_timestamp="${
      params.oauth_timestamp
    }", oauth_consumer_key="${X_OAUTH_CONSUMER_KEY}", oauth_signature="${encodeURIComponent(
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
      encodeURIComponent(X_OAUTH_CONSUMER_SECRET) +
      '&' +
      encodeURIComponent(oauthTokenSecret);
    const oauthSignature = generateHamcSignature(signingKey, baseString);

    const authorizationHeader = `OAuth oauth_consumer_key="${X_OAUTH_CONSUMER_KEY}", oauth_nonce="${
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
  ): string {
    try {
      const headerParams = {
        oauth_consumer_key: X_OAUTH_CONSUMER_KEY,
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
        X_OAUTH_CONSUMER_SECRET,
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
