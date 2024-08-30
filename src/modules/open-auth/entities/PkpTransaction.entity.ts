import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { BridgeTokens } from './BridgeTokens.entity';

@Schema()
export class PkpTransaction {
  @Prop({ required: true })
  to: string;

  @Prop({ required: true })
  from: string;

  @Prop({ required: true })
  chainId: number;

  @Prop({ required: true })
  blockHash: string;

  @Prop({ required: true })
  blockNumber: number;

  @Prop({ required: true })
  transactionHash: string;

  @Prop({ required: true })
  status: string;

  @Prop({ required: true })
  amountTransferred: string;

  @Prop()
  data: string;

  @Prop({ type: BridgeTokens })
  tokenTransfer: BridgeTokens;

  @Prop({ default: 0 })
  createdAt: number;
}

export type PkpTransactionDocument = PkpTransaction & Document;

export const PkpTransactionSchema =
  SchemaFactory.createForClass(PkpTransaction);
