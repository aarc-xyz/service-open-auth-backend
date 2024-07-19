import { BigNumberish } from 'ethers';

export class TransactionDto {
  to: string;
  value?: BigNumberish;
  data?: string;
}

export class SignerDto {
  wallet_address: string;
  sessionKey: string;
  chainId: number;
}

export class SignMessageDto extends SignerDto {
  message: string;
}

export class TransactionsOperationDto extends SignerDto {
  transaction: TransactionDto;
}
