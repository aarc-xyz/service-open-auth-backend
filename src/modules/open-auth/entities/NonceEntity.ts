import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { AccountType } from '../utils/types.interfaces';

@Schema()
export class NonceUsed {
  @Prop({ unique: true, index: true, required: true })
  nonce: string;
}

export type NonceUsedDocument = NonceUsed & Document;

export const NonceUsedSchema = SchemaFactory.createForClass(NonceUsed);
