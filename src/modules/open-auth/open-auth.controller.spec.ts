import { Test, TestingModule } from '@nestjs/testing';
import { OpenAuthController } from './open-auth.controller';
import { OpenAuthService } from './open-auth.service';
import { LitClient } from './clients/Lit.client';
import { AccountsRepository } from './repositories/accounts.repository';
import { StytchClient } from './clients/Stytch.client';
import { FarcasterAuthProvider } from './authProviders/Farcaster.authProvider';
import { TelegramAuthProvider } from './authProviders/Telegram.authProvider';
import { SessionsRepository } from './repositories/sessions.repository';
import { PkpTransactionsRepository } from './repositories/pkptransactions.repository';
import { NonceUsedRepository } from './repositories/nonce.repository';
import { TwitterAuthProvider } from './authProviders/Twitter.authProvider';
import { TokenAndSecretRepository } from './repositories/tokenAndSecret.repository';
import { PlatformAuthClient } from "./clients/PlatformAuth.client";
import { NativeAuthClient } from "./clients/NativeAuth.client";
import { TwilioAuthProvider } from "./authProviders/Twilio.authProvider";
import { OAuthClientDataRepository } from "./repositories/oAuthClientData.repository";
import { PassKeyRepository } from "./repositories/passKeys.repository";
import { GoogleAuthProvider } from "./authProviders/Google.authProvider";
import { WebAuthnProvider } from "./authProviders/Webauthn.authProvider";

describe('OpenAuthController', () => {
  let controller: OpenAuthController;

  const mockLitClient = {
    close: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [OpenAuthController],
      providers: [
        OpenAuthService,
        LitClient,
        { provide: LitClient, useValue: mockLitClient },
        PlatformAuthClient,
        { provide: PlatformAuthClient, useValue: PlatformAuthClient },
        NativeAuthClient,
        { provide: NativeAuthClient, useValue: NativeAuthClient },
        StytchClient,
        { provide: StytchClient, useValue: StytchClient },
        GoogleAuthProvider,
        { provide: GoogleAuthProvider, useValue: GoogleAuthProvider },
        TwilioAuthProvider,
        { provide: TwilioAuthProvider, useValue: TwilioAuthProvider },
        FarcasterAuthProvider,
        { provide: FarcasterAuthProvider, useValue: FarcasterAuthProvider },
        TwitterAuthProvider,
        { provide: TwitterAuthProvider, useValue: TwitterAuthProvider },
        TelegramAuthProvider,
        { provide: TelegramAuthProvider, useValue: TelegramAuthProvider },
        WebAuthnProvider,
        { provide: WebAuthnProvider, useValue: WebAuthnProvider },
        AccountsRepository,
        { provide: AccountsRepository, useValue: AccountsRepository },
        SessionsRepository,
        { provide: SessionsRepository, useValue: SessionsRepository },
        PkpTransactionsRepository,
        {
          provide: PkpTransactionsRepository,
          useValue: PkpTransactionsRepository,
        },
        NonceUsedRepository,
        {
          provide: NonceUsedRepository,
          useValue: NonceUsedRepository,
        },
        TokenAndSecretRepository,
        {
          provide: TokenAndSecretRepository,
          useValue: TokenAndSecretRepository,
        },
        OAuthClientDataRepository,
        {
          provide: OAuthClientDataRepository,
          useValue: OAuthClientDataRepository,
        },
        PassKeyRepository,
        { provide: PassKeyRepository, useValue: PassKeyRepository },
      ],
    }).compile();

    controller = module.get<OpenAuthController>(OpenAuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
