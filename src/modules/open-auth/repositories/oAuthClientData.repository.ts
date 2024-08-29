import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ServiceError } from '../common/types';
import {
  OAuthClientData,
  OAuthClientDataDocument,
} from '../entities/OAuthClientData.entity';
import { Provider } from '../common/types';

@Injectable()
export class OAuthClientDataRepository {
  private readonly logger = new Logger(OAuthClientDataRepository.name);

  constructor(
    @InjectModel(OAuthClientData.name)
    private clientDataModel: Model<OAuthClientDataDocument>,
  ) {}

  async findOneByKey(
    id: string,
    provider: Provider,
  ): Promise<OAuthClientDataDocument | null> {
    try {
      const documents = await this.clientDataModel.findOne({
        clientId: id,
        provider: provider,
      });

      return documents;
    } catch (error) {
      this.logger.error(error);
      throw new ServiceError('Error fetching client OAuth data');
    }
  }

  async addOrUpdateClientData(
    data: OAuthClientData,
  ): Promise<OAuthClientDataDocument> {
    try {
      // Ensure that the entry is unique by the apiKeyHash and provider
      // Delete the existing entry if it exists, considering this is an update request
      await this.clientDataModel.deleteMany({
        clientId: data.clientId,
        provider: data.provider,
      });

      const payload = new this.clientDataModel(data);
      return await payload.save();
    } catch (error) {
      this.logger.error(error);
      throw new ServiceError('Error saving client OAuth data');
    }
  }
}
