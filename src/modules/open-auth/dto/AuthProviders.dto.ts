import { IsNotEmpty, IsString } from 'class-validator';
import { Provider } from '../common/types';
import { Transform } from 'class-transformer';
import { encryptData } from '../common/helpers';

export type ClientCredentials = Record<string, unknown>;

// Google OAuth2 client secrets
export type GoogleClientSecrets = {
  clientId: string;
  clientSecret: string;
};

// Telegram OAuth2 client secrets
export type TelegramClientSecrets = {
  botName: string;
  botToken: string;
}

// X (Twitter) OAuth2 client secrets
export type XClientSecrets = {
  consumerKey: string;
  consumerSecret: string;
  oauthCallback: string;
}

export class AuthProvidersDto {
  @IsString()
  @IsNotEmpty()
  provider: Provider;

  // This is a generic object that can be used to store any kind of client credentials
  @IsNotEmpty()
  @Transform(({ value }) => {
    const encryptedCredentials: ClientCredentials = {};
    Object.keys(value).forEach((key) => {
      encryptedCredentials[key] = encryptData(value[key]);
    });
    return encryptedCredentials;
  })
  credentials: ClientCredentials;
}
