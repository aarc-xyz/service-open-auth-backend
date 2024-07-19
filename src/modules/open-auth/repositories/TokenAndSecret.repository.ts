import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import {
  TokenAndSecret,
  TokenAndSecretDocument,
} from '../entities/TokenAndSecret';
import { Model } from 'mongoose';
import { ServiceError } from '../utils/types.interfaces';

@Injectable()
export class TokenAndSecretRepository {
  private readonly logger: Logger = new Logger(TokenAndSecretRepository.name);

  constructor(
    @InjectModel(TokenAndSecret.name)
    private tokenAndSecretModel: Model<TokenAndSecretDocument>,
  ) {}

  async findOneByKey(
    value: string,
    key = 'token',
  ): Promise<TokenAndSecretDocument | null> {
    try {
      const document = await this.tokenAndSecretModel.findOne({
        [key]: value,
      });

      // Delete the document from db after pulling it
      if (document) {
        await this.tokenAndSecretModel.deleteOne({
          [key]: value,
        });
      }
      return document;
    } catch (error) {
      this.logger.error('Error finding token and secret', error);
      throw new ServiceError('Error finding token and secret');
    }
  }

  async addTokenAndSecret(
    token: string,
    secret: string,
  ): Promise<TokenAndSecretDocument> {
    try {
      const data: { [key: string]: string } = { token, secret };
      const payload = new this.tokenAndSecretModel(data);
      return await payload.save();
    } catch (error) {
      this.logger.error('Error adding token and secret', error);
      throw new ServiceError('Error adding token and secret');
    }
  }
}
