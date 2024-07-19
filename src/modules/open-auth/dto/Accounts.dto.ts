import { Transform } from 'class-transformer';
import { IsNotEmpty, IsString } from 'class-validator';
import { Provider } from '../utils/types.interfaces';

export class ResolveAccountDto {
  @IsString()
  @IsNotEmpty()
  provider!: Provider;

  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.toLowerCase(), { toClassOnly: true })
  primary_contact: string;
}

export class ClaimAccountDto {
  @IsString()
  @IsNotEmpty()
  provider: Provider;

  @IsString()
  @IsNotEmpty()
  authKey: string;

  session_identifier: string;
  expiration: number;
}

export class FarcasterAuthDto {
  @IsString()
  @IsNotEmpty()
  nonce: string;
  domain: string;
  message: string;
  signature: string;
}

export class XAuthDto {
  @IsString()
  @IsNotEmpty()
  oauth_token: string;

  @IsString()
  @IsNotEmpty()
  oauth_verifier: string;
}

// It is imperative that the names of the fields in the TelegramAuthDto doesn't change, as they are used to verify the hash
export class TelegramAuthDto {
  id?: string;
  auth_date: number;
  first_name?: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  hash?: string;
}

export class GetPubKeyDto {
  @IsString()
  @IsNotEmpty()
  provider: Provider;

  @IsString()
  @IsNotEmpty()
  session_identifier: string;
  // oauth
  authKey?: string;

  @IsNotEmpty()
  chainId: number;

  expiration?: number;
  code?: string;
  method_id?: string;
  phone_number?: string;
  farcaster_session?: FarcasterAuthDto;

  // for X Auth
  x_session?: XAuthDto;

  telegram_session?: TelegramAuthDto;
}

export class ValidateOTPDto {
  @IsNotEmpty()
  method_id: string;

  // twitter jwt token
  @IsString()
  @IsNotEmpty()
  otp: string;
}

export class ExternalWalletDto {
  address: string;
  message: string;
  signature: string;
  walletType: string;
}
