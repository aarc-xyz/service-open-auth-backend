import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Mixed, SchemaTypes } from 'mongoose';
import { Provider } from '../common/types';

@Schema()
export class OAuthClientData {
  @Prop({ required: true })
  apiKeyHash: string;

  @Prop({ unique: true, required: true, type: SchemaTypes.Mixed })
  credentials: Record<string, Mixed>;

  @Prop({ required: true })
  provider: Provider;
}

export type OAuthClientDataDocument = OAuthClientData & Document;
export const OAuthClientDataSchema =
  SchemaFactory.createForClass(OAuthClientData);
