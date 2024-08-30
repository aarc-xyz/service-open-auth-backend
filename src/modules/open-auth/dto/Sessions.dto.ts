import { IsNotEmpty, IsString } from 'class-validator';
import { Provider } from '../common/types';
import { Transform } from 'class-transformer';

export class SessionKeyDto {
  @IsString()
  @IsNotEmpty()
  provider: Provider;

  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.toLowerCase(), { toClassOnly: true })
  session_identifier: string;

  @IsString()
  authKey?: string;

  @IsNotEmpty()
  chainId: number;

  expiration: number;
}

export class PollSession {
  @IsString()
  @IsNotEmpty()
  provider: Provider;

  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.toLowerCase(), { toClassOnly: true }) // Transform address to lowercase
  session_identifier: string;
}
