import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class BridgeTokens {
  @Prop({ required: true })
  address: string;

  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  symbol: string;

  @Prop({ required: true })
  decimals: number;

  @Prop({ required: true })
  logoURI: string;

  @Prop({ required: true })
  source: string[];

  @Prop({ required: true })
  chainId: number;
}

export type BridgeTokensDocument = BridgeTokens & Document;

export const BridgeTokensSchema = SchemaFactory.createForClass(BridgeTokens);
