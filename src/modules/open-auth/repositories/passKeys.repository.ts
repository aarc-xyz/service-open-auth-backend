import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { PassKey, PassKeyDocument } from '../entities/PassKeys.entity';

@Injectable()
export class PassKeyRepository {
  constructor(
    @InjectModel(PassKey.name) private passKeyModel: Model<PassKeyDocument>,
  ) {}

  async findOneByKey(
    params: Record<string, string>,
  ): Promise<PassKeyDocument | null> {
    const documents = await this.passKeyModel
      .findOne({
        ...params,
      })
      .sort({ _id: -1 });
    return documents;
  }

  async findManyByKey(
    value: string,
    key = 'userId',
  ): Promise<PassKeyDocument[]> {
    const documents = await this.passKeyModel.find({ [key]: value });
    return documents;
  }

  async updatePassKey(
    value: string,
    key = 'challenge',
    data: Partial<PassKey>,
  ): Promise<PassKeyDocument | null> {
    const document = await this.passKeyModel.findOneAndUpdate(
      { [key]: value },
      { $set: data },
    );
    return;
  }

  async addPassKey(data: PassKey): Promise<PassKeyDocument> {
    const payload = new this.passKeyModel(data);
    return await payload.save();
  }
}
