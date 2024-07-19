import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { NonceUsed, NonceUsedDocument } from '../entities/NonceEntity';

@Injectable()
export class NonceUsedRepository {
  constructor(
    @InjectModel(NonceUsed.name) private nonceModel: Model<NonceUsedDocument>,
  ) {}

  async findOneByKey(
    value: string,
    key = 'nonce',
  ): Promise<NonceUsedDocument | null> {
    const documents = await this.nonceModel.findOne({ [key]: value });
    return documents;
  }

  async addNonce(value: string): Promise<NonceUsedDocument> {
    const data: { [key: string]: unknown } = { nonce: value };
    const payload = new this.nonceModel(data);
    return await payload.save();
  }
}
