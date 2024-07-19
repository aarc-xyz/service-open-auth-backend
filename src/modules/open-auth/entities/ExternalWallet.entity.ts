import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { AccountType } from '../utils/types.interfaces';

@Schema()
export class ExternalWallet {
  @Prop({ index: true, required: true })
  address: string;

  @Prop({ default: AccountType.EXTERNAL })
  walletType: string;

  @Prop({ default: 1 })
  loginCount: number;

  @Prop({ default: 0 })
  createdAt: number;

  @Prop({ default: 0 })
  lastLoginAt: number;

  @Prop({ default: '', required: true })
  apiKeyId: string;
}

export type ExternalWalletDocument = ExternalWallet & Document;

export const ExternalWalletSchema =
  SchemaFactory.createForClass(ExternalWallet);
