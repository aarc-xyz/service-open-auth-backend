import * as crypto from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { TelegramAuthDto } from '../dto/Accounts.dto';
import { ServiceError } from '../utils/types.interfaces';
import {
  TELEGRAM_AUTH_VALID_DURATION,
  TELEGRAM_BOT_TOKEN,
} from '../utils/constants';

@Injectable()
export class TelegramClient {
  private readonly logger: Logger = new Logger(TelegramClient.name);
  private readonly BOT_TOKEN: string;

  constructor() {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_BOT_TOKEN.length) {
      throw new ServiceError('Telegram bot token is not provided');
    }
    this.BOT_TOKEN = TELEGRAM_BOT_TOKEN;
    this.logger.log('TelegramClient initialized');
  }

  async verify(params: TelegramAuthDto): Promise<boolean> {
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

      return true;
    } catch (error) {
      this.logger.error('Failed to verify telegram data', error);
      return false;
    }
  }
}
