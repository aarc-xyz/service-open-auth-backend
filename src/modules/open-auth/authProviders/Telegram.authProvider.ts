import * as crypto from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { TelegramAuthDto } from '../dto/Accounts.dto';
import { AuthMethodResponseObject, Provider, ServiceError } from "../common/types";
import {
  LIT_CUSTOM_AUTH_TYPE_ID,
  TELEGRAM_AUTH_VALID_DURATION,
  TELEGRAM_BOT_TOKEN
} from "../common/constants";
import { BaseAuthProvider } from "./Base.authProvider";
import { OAuthClientDataRepository } from "../repositories/oAuthClientData.repository";
import { Mixed } from "mongoose";
import { customAuthMethod, decryptData } from "../common/helpers";

@Injectable()
export class TelegramAuthProvider extends BaseAuthProvider {
  private readonly BOT_TOKEN: string;

  constructor(
    private readonly oauthClientDataRepository: OAuthClientDataRepository,
  ) {
    super(Provider.TELEGRAM, TelegramAuthProvider.name);
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_BOT_TOKEN.length) {
      throw new ServiceError('Telegram bot token is not provided');
    }
    this.BOT_TOKEN = TELEGRAM_BOT_TOKEN;
    this.logger.log('TelegramAuthProvider initialized');
  }

  async registerCredentials(apiKeyHash: string, botName: string, botToken: string): Promise<void> {
    try {
      await this.oauthClientDataRepository.addOrUpdateClientData({
        apiKeyHash: apiKeyHash,
        provider: Provider.TELEGRAM,
        credentials: {
          botToken: botToken as unknown as Mixed,
          botName: botName as unknown as Mixed,
        },
      })
    } catch (error) {
      this.logger.error('Error registering credentials', error);
      throw new ServiceError('Error registering credentials', error);
    }
  }

  async generateCallbackUrl(apiKeyHash: string): Promise<string> {
    try {
      const clientData = await this.oauthClientDataRepository.findOneByKey(
        apiKeyHash,
        Provider.TELEGRAM,
      );

      if (!clientData) {
        this.logger.error('Client data not found');
        throw new ServiceError('Client data not found');
      }

      const encryptedBotName: string = clientData.credentials['botName'] as unknown as string;
      if (!encryptedBotName) {
        this.logger.error('Client not registered, telegram bot token not found');
        throw new ServiceError('Client not registered, telegram bot token not found');
      }

      return decryptData(encryptedBotName);
    } catch (error) {
      this.logger.error('Error generating callback url', error);
      throw new ServiceError('Error generating callback url', error);
    }
  }

  async verify(params: TelegramAuthDto): Promise<AuthMethodResponseObject> {
    try {
      if (params.auth_date * 1000 < Date.now() - TELEGRAM_AUTH_VALID_DURATION) {
        throw new ServiceError('Auth date is expired');
      }

      // delete the params that are undefined
      Object.keys(params).forEach(
        (key) => params[key] === undefined && delete params[key],
      );

      // verify the hash
      const requestHash = params.hash;
      delete params.hash;
      const key = crypto.createHash('sha256').update(this.BOT_TOKEN).digest();

      // generate query string from the params with params in alphabetical order`
      const queryString = Object.keys(params)
        .sort()
        .map((key) => `${key}=${params[key]}`)
        .join('\n');
      const paramsHash = crypto
        .createHmac('sha256', key)
        .update(queryString)
        .digest('hex');

      if (requestHash !== paramsHash) {
        throw new ServiceError('Invalid hash');
      }

      const customAuth = customAuthMethod(params.id);
      return {
        authMethod: {
          authMethodType: LIT_CUSTOM_AUTH_TYPE_ID,
          accessToken: null
        },
        authId: customAuth.id,
        primary_contact: params.id,
      }
    } catch (error) {
      this.logger.error('Failed to verify telegram data', error);
      throw new ServiceError('Failed to verify telegram data', error);
    }
  }
}
