import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class PassKey {
  @Prop({ unique: true, index: true, required: true })
  id: string;

  @Prop({ type: String })
  credentialId?: string;

  @Prop({ unique: false })
  webAuthnPublicKey?: Buffer;

  @Prop({ required: true, unique: true })
  challenge: string;

  @Prop({ required: true })
  primary_contact: string;

  @Prop({ required: true })
  wallet_address: string;

  @Prop({ required: true })
  counter: number;
}

export type PassKeyDocument = PassKey & Document;

export const PassKeySchema = SchemaFactory.createForClass(PassKey);
