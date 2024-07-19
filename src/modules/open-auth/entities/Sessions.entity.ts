import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';
import { AccountUser, AccountsDocument } from './Accounts.entity';
import { SessionSigs } from '@lit-protocol/types';

@Schema()
export class Sessions {
  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'Accounts' }) // Reference to the User entity
  accountId: AccountsDocument;

  @Prop({ type: Object })
  sessionSigs: SessionSigs;

  @Prop()
  expiresAt: Date;

  @Prop({ type: AccountUser })
  user: AccountUser;

  @Prop({ default: 0 })
  createdAt: number;

  @Prop({ default: 0 })
  updatedAt: number;

  @Prop({ required: true, unique: true })
  session_identifier: string;

  @Prop({ required: true })
  apiKeyId: string;

  @Prop({ default: false })
  polled: boolean;

  @Prop({ required: true })
  wallet_address: string;
}

export type SessionsDocument = Sessions & Document;

export const SessionsSchema = SchemaFactory.createForClass(Sessions);
