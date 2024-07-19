import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { LitClient } from './client/Lit.client';
import { StytchClient } from './client/Stytch.client';
import { FarcasterClient } from './client/Farcaster.client';
import { TwitterClient } from './client/Twitter.client';
import { TelegramClient } from './client/Telegram.client';
import { Accounts, AccountsSchema } from './entities/Accounts.entity';
import {
  ExternalWallet,
  ExternalWalletSchema,
} from './entities/ExternalWallet.entity';
import { Sessions, SessionsSchema } from './entities/Sessions.entity';
import { OpenAuthController } from './open-auth.controller';
import { OpenAuthService } from './open-auth.service';
import { AccountsRepository } from './repositories/accounts.repository';
import { SessionsRepository } from './repositories/sessions.repository';
import {
  PkpTransaction,
  PkpTransactionSchema,
} from './entities/PkpTransaction.entity';
import { PkpTransactionsRepository } from './repositories/pkptransactions.repository';
import {
  BridgeTokens,
  BridgeTokensSchema,
} from './entities/BridgeTokens.entity';
import { NonceUsed, NonceUsedSchema } from './entities/NonceEntity';
import { NonceUsedRepository } from './repositories/nonce.repository';
import { TokenAndSecretRepository } from './repositories/TokenAndSecret.repository';
import {
  TokenAndSecret,
  TokenAndSecretSchema,
} from './entities/TokenAndSecret';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Accounts.name, schema: AccountsSchema },
      { name: Sessions.name, schema: SessionsSchema },
      { name: ExternalWallet.name, schema: ExternalWalletSchema },
      { name: NonceUsed.name, schema: NonceUsedSchema },
      { name: PkpTransaction.name, schema: PkpTransactionSchema },
      { name: BridgeTokens.name, schema: BridgeTokensSchema },
      { name: TokenAndSecret.name, schema: TokenAndSecretSchema },
    ]),
    MongooseModule.forRoot(process.env.DB_URL),
  ],
  controllers: [OpenAuthController],
  providers: [
    OpenAuthService,
    LitClient,
    AccountsRepository,
    StytchClient,
    FarcasterClient,
    TwitterClient,
    TelegramClient,
    SessionsRepository,
    PkpTransactionsRepository,
    NonceUsedRepository,
    TokenAndSecretRepository,
  ],
  exports: [StytchClient, NonceUsedRepository],
})
export class OpenAuthModule {}
