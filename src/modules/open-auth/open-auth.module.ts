import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { LitClient } from './clients/Lit.client';
import { StytchClient } from './clients/Stytch.client';
import { FarcasterAuthProvider } from './authProviders/Farcaster.authProvider';
import { TwitterAuthProvider } from './authProviders/Twitter.authProvider';
import { TelegramAuthProvider } from './authProviders/Telegram.authProvider';
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
import { TokenAndSecretRepository } from './repositories/tokenAndSecret.repository';
import {
  TokenAndSecret,
  TokenAndSecretSchema,
} from './entities/TokenAndSecret';
import { PlatformAuthClient } from "./clients/PlatformAuth.client";
import { NativeAuthClient } from "./clients/NativeAuth.client";
import { TwilioAuthProvider } from "./authProviders/Twilio.authProvider";
import { WebAuthnProvider } from "./authProviders/Webauthn.authProvider";
import { OAuthClientDataRepository } from "./repositories/oAuthClientData.repository";
import { OAuthClientData, OAuthClientDataSchema } from "./entities/OAuthClientData.entity";
import { GoogleAuthProvider } from "./authProviders/Google.authProvider";
import { BaseAuthProvider } from "./authProviders/Base.authProvider";
import { PassKey, PassKeySchema } from "./entities/PassKeys.entity";
import { PassKeyRepository } from "./repositories/passKeys.repository";

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
      { name: OAuthClientData.name, schema: OAuthClientDataSchema },
      { name: PassKey.name, schema: PassKeySchema },
    ]),
    MongooseModule.forRoot(process.env.DB_URL),
  ],
  controllers: [OpenAuthController],
  providers: [
    OpenAuthService,
    PlatformAuthClient,
    NativeAuthClient,
    LitClient,
    StytchClient,
    GoogleAuthProvider,
    TwilioAuthProvider,
    WebAuthnProvider,
    FarcasterAuthProvider,
    TwitterAuthProvider,
    TelegramAuthProvider,
    AccountsRepository,
    SessionsRepository,
    PkpTransactionsRepository,
    NonceUsedRepository,
    TokenAndSecretRepository,
    OAuthClientDataRepository,
    PassKeyRepository,
  ],
  exports: [],
})
export class OpenAuthModule {}
