import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class TokenAndSecret {
  @Prop({ required: true, unique: true })
  token: string;

  @Prop({ required: true })
  secret: string;
}

export type TokenAndSecretDocument = TokenAndSecret & Document;
export const TokenAndSecretSchema =
  SchemaFactory.createForClass(TokenAndSecret);
