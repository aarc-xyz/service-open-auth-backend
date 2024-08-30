import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { AccountType } from '../common/types';

@Schema()
export class AccountUser {
  @Prop()
  first_name?: string;

  @Prop()
  last_name?: string;

  @Prop()
  middle_name?: string;

  @Prop()
  primary_contact?: string;

  @Prop()
  profile_picture_url?: string;
}

@Schema()
export class Accounts {
  @Prop({ unique: true, index: true, required: false })
  pkpAddress: string;

  @Prop({ unique: true, index: true, required: true })
  publicKey: string;

  @Prop({ unique: true, index: true })
  keyId: string;

  @Prop({ unique: true, index: true })
  userId: string;

  @Prop()
  authProvider: string;

  @Prop({ type: AccountUser })
  user: AccountUser;

  @Prop({ default: null })
  litAuthId: string;

  @Prop({ required: false })
  tokenId: string;

  @Prop({ default: false })
  claimed: boolean;

  @Prop({ default: AccountType.RESOLVED })
  accountType: string;

  @Prop({ default: 0 })
  createdAt: number;

  @Prop({ default: 0 })
  updatedAt: number;
}

export type AccountsDocument = Accounts & Document;

export const AccountsSchema = SchemaFactory.createForClass(Accounts);
