import { PKPEthersWallet } from '@lit-protocol/pkp-ethers';
import { SessionSigs } from '@lit-protocol/types';
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';
import { OTPsEmailLoginOrCreateResponse } from 'stytch';
import { v4 } from 'uuid';
import { sign, verify } from 'jsonwebtoken';
import { ServiceError } from './common/types';
import {
  deconstructSessionSigs, generateAuthConditions,
  generateLitKeyId,
  reconstructSessionSigs
} from "./common/helpers";
import { MESSAGES, RESPONSE_CODES } from './common/response.messages';
import { TwitterAuthProvider } from './authProviders/Twitter.authProvider';
import { LitClient } from './clients/Lit.client';
import { StytchClient } from './clients/Stytch.client';
import {
  ClaimAccountDto,
  ExternalWalletDto,
  GetPubKeyDto, RegisterWebAuthnDto
} from "./dto/Accounts.dto";
import { PollSession, SessionKeyDto } from './dto/Sessions.dto';
import {
  SignerDto,
  SignMessageDto,
  TransactionsOperationDto,
} from './dto/Transactions.dto';
import { Accounts, AccountUser } from './entities/Accounts.entity';
import { PkpTransactionDocument } from './entities/PkpTransaction.entity';
import { AccessControlConditions, SessionsDocument } from "./entities/Sessions.entity";
import { AccountsRepository } from './repositories/accounts.repository';
import { PkpTransactionsRepository } from './repositories/pkptransactions.repository';
import { SessionsRepository } from './repositories/sessions.repository';
import {
  TIMESTAMP_REGEX,
  ZERO_ADDRESS,
} from './common/constants';
import {
  AccountType,
  AccountUserData,
  AuthMethodResponseObject,
  PkpSigningPermissions,
  PkpTransactionData,
  Provider,
  TransactionStatus,
} from './common/types';
import { NonceUsedRepository } from './repositories/nonce.repository';
import { AuthProvidersDto } from "./dto/AuthProviders.dto";
import { NativeAuthClient } from "./clients/NativeAuth.client";
import { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/types";
import { WebAuthnProvider } from "./authProviders/Webauthn.authProvider";
import { Request } from "express";
import { TwilioAuthProvider } from "./authProviders/Twilio.authProvider";
import { PlatformAuthClient } from "./clients/PlatformAuth.client";

@Injectable()
export class OpenAuthService {
  private readonly logger = new Logger(OpenAuthService.name);
  constructor(
    private readonly litClient: LitClient,
    private readonly platformAuthClient: PlatformAuthClient,
    private readonly nativeAuthClient: NativeAuthClient,
    private readonly stytchClient: StytchClient,
    private readonly twilioAuthProvider: TwilioAuthProvider,
    private readonly webAuthnClient: WebAuthnProvider,
    private readonly twitterClient: TwitterAuthProvider,
    private readonly accountsRepository: AccountsRepository,
    private readonly sessionsRepository: SessionsRepository,
    private readonly pkpTxnRepository: PkpTransactionsRepository,
    private readonly nonceRepository: NonceUsedRepository,
  ) {
    this.litClient.close();
  }

  async addCredentials(
    addAuthProviderDto: AuthProvidersDto,
    keyHash: string,
  ): Promise<void> {
    try {
      await this.nativeAuthClient.registerCredentials(
        addAuthProviderDto.provider,
        keyHash,
        addAuthProviderDto.credentials,
      );
    } catch (error) {
      this.logger.error('Error in adding native provider', error);
      throw new ServiceError('Error in adding native provider', error);
    }
  }

  async getClientCallbackUrl(
    provider: Provider,
    keyHash: string,
    state?: string
  ): Promise<{
    hasNativeAuth: boolean;
    callbackUrl: string;
  }> {
    try {
      return await this.nativeAuthClient.getCallbackUrl(provider, keyHash, state);
    } catch (error) {
      this.logger.error('Error in getting client callback url', error);
      throw new ServiceError('Error in getting client callback url', error);
    }
  }

  async generateWebAuthnRegistrationOpts(
    req: Request,
    sessionIdentifier: string,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    try {
      const session = await this.sessionsRepository.findOne({
        session_identifier: sessionIdentifier,
      });

      if (!session) {
        throw new ServiceError('Session not found');
      }

      if (!session.polled) {
        throw new ServiceError('Session not polled');
      }

      // check if session is expired
      if (session.expiresAt < new Date()) {
        throw new ServiceError('Session expired');
      }

      const primary_contact = session.user.primary_contact;

      const existingAccount = await this.accountsRepository.findOneByKey(
        'user.primary_contact',
        primary_contact,
      );
      if (!existingAccount) {
        throw new ServiceError('Account does not exists');
      }

      return await this.webAuthnClient.generateUserRegistrationOptions(
        req.headers.origin,
        primary_contact,
        session.wallet_address,
      );
    } catch (error) {
      this.logger.error('Error in generating registration options', error);
      throw new ServiceError('Error in generating registration options', error);
    }
  }

  async registerWithWebAuthn(
    req: Request,
    webAuthnDto: RegisterWebAuthnDto,
  ): Promise<boolean> {
    try {
      const existingAccount = await this.accountsRepository.findOneByKey(
        'pkpAddress',
        webAuthnDto.wallet_address,
      );
      if (!existingAccount) {
        throw new ServiceError('Account does not exist');
      }
      return await this.webAuthnClient.verifyRegistration(
        req.headers.origin,
        webAuthnDto,
      );
    } catch (error) {
      this.logger.error('Error in registering webauthn', error);
      throw new ServiceError('Error in registering webauthn', error);
    }
  }

  async authenticateLitSession(
    authKey: string,
    provider: string,
  ): Promise<AuthMethodResponseObject> {
    await this.litClient.init();
    const sessionResponse = await this.stytchClient.handleProviderOauth(
      authKey,
    );

    const authMethodResponse = await this.litClient.generateProviderAuthMethod(
      sessionResponse.session_jwt,
    );
    authMethodResponse['primary_contact'] =
      sessionResponse?.user?.emails[0]?.email;
    authMethodResponse['user'] = sessionResponse.user.name;
    for (const auth_provider of sessionResponse.user.providers) {
      if (auth_provider.provider_type.toLowerCase() == provider) {
        authMethodResponse['profile_picture_url'] =
          auth_provider?.profile_picture_url;
        break;
      }
    }
    return authMethodResponse;
  }

  async claimAccount(claimAccountDto: ClaimAccountDto): Promise<{
    pkpAddress: string;
    pkpPublicKey: string;
    tokenId: string;
  } | null> {
    await this.litClient.init();
    const authMethodResponse: AuthMethodResponseObject =
      await this.authenticateLitSession(
        claimAccountDto.authKey,
        claimAccountDto.provider,
      );

    const existingAccount = await this.accountsRepository.findOneByKey(
      'user.primary_contact',
      authMethodResponse.primary_contact,
    );
    if (!existingAccount) {
      throw new ServiceError('Account does not exist');
    }
    if (existingAccount.claimed) {
      throw new ServiceError('Account already claimed');
    }

    const pkpObject = await this.litClient.claimKeyId(
      existingAccount.userId,
      authMethodResponse,
      claimAccountDto.provider,
    );
    if (pkpObject) {
      await this.accountsRepository.updateAccount(existingAccount);
      return pkpObject;
    } else {
      return null;
    }
  }

  async getSessionKey(
    sessionKeyDto: SessionKeyDto,
    userAccountId: string,
    pkpPublicAddress: string,
    signingPermissions: PkpSigningPermissions,
    accessControlConditions: AccessControlConditions,
    authMethodObject?: AuthMethodResponseObject,
  ): Promise<SessionSigs> {
    await this.litClient.init();
    const existingSession = await this.sessionsRepository.findOne({
      session_identifier: sessionKeyDto.session_identifier,
      // can cause duplicate key error in case of same session identifier in case if session was never polled
      expiresAt: { $gt: new Date() },
    });
    if (existingSession) {
      this.logger.log(existingSession);
      return existingSession._id as SessionSigs;
    }

    const authMethodResponse = authMethodObject
      ? authMethodObject
      : await this.authenticateLitSession(
        sessionKeyDto.authKey,
        sessionKeyDto.provider,
      );

    let sessionSig;

    if (signingPermissions.stytch) {
      sessionSig = await this.litClient.getSessionSigs(
        authMethodResponse.authMethod,
        pkpPublicAddress,
        sessionKeyDto.chainId,
        new Date(Date.now() + 1000 * 60 * 60 * 24),
      );
    } else {
      const start_time = performance.now();
      sessionSig = await this.litClient.getCustomAuthSessionSigs(
        {
          id: authMethodObject.authId,
          type: authMethodResponse.authMethod.authMethodType,
        },
        pkpPublicAddress,
        sessionKeyDto.chainId,
      );
      const end_time = performance.now();
      this.logger.log(
        'Time taken to get custom auth session sigs: ',
        end_time - start_time,
      );
    }

    const sessionUser = {
      ...authMethodObject.user,
      primary_contact: authMethodObject.primary_contact,
      profile_picture_url: authMethodObject.profile_picture_url,
    };

    const dbResponse = await this.sessionsRepository.createSession(
      sessionSig,
      sessionUser,
      new Date(sessionKeyDto.expiration),
      userAccountId,
      sessionKeyDto.session_identifier,
      sessionKeyDto.apiKeyId,
      ethers.utils.computeAddress(pkpPublicAddress),
      accessControlConditions,
    );
    return sessionSig;
  }

  async validateSigner(signerDto: SignerDto): Promise<PKPEthersWallet> {
    try {
      await this.litClient.init();
      if (!signerDto.sessionKey) {
        throw new ServiceError('Client Session Key not provided');
      }

      const sessionSigDocument: SessionsDocument =
        await this.sessionsRepository.findOne({
          wallet_address: signerDto.wallet_address,
        });

      let sessionSig: SessionSigs = sessionSigDocument.sessionSigs;
      if (sessionSigDocument) {
        if (sessionSigDocument.expiresAt < new Date()) {
          throw new ServiceError('Session expired');
        }

        try {
          const accessConditions: AccessControlConditions =
            sessionSigDocument.accessControlConditions;
          const jwtKey: string = generateAuthConditions(accessConditions);
          const decodedSessionKey = verify(signerDto.sessionKey, jwtKey);
          const clientKey = decodedSessionKey['clientKey'];

          sessionSig = reconstructSessionSigs(
            clientKey.toString(),
            sessionSigDocument.sessionSigs,
          );
        } catch (error) {
          throw new ServiceError('Invalid session key');
        }
      } else {
        throw new ServiceError("Session doesn't exist for this user");
      }
      const existingAccount = await this.accountsRepository.findOneByKey(
        '_id',
        sessionSigDocument.accountId._id as string,
      );

      if (!existingAccount) {
        throw new ServiceError('Account does not exist');
      }
      if (!existingAccount.claimed) {
        throw new ServiceError('Account not claimed');
      }

      return await this.litClient.getPKPEtherWallet(
        existingAccount.publicKey,
        sessionSig,
        signerDto.chainId,
      );
    } catch (error) {
      this.logger.error(`Error in validating signer:`);
      this.logger.error(error);
      throw new ServiceError('Error in validating signer', error);
    }
  }

  async signUserMessage(signMessageDto: SignMessageDto): Promise<string> {
    try {
      await this.litClient.init();
      const pkpWallet = await this.validateSigner({
        wallet_address: signMessageDto.wallet_address,
        sessionKey: signMessageDto.sessionKey,
        chainId: signMessageDto.chainId,
      });
      await pkpWallet.init();
      const signedMessage = await pkpWallet.signMessage(signMessageDto.message);
      return signedMessage;
    } catch (error) {
      this.logger.error('Error in signing message', JSON.parse(error));
      throw new ServiceError('Message sign error', error);
    }
  }

  async signUserTransactions(
    signTransactionDto: TransactionsOperationDto,
  ): Promise<string> {
    try {
      await this.litClient.init();
      const pkpWallet = await this.validateSigner({
        wallet_address: signTransactionDto.wallet_address,
        sessionKey: signTransactionDto.sessionKey,
        chainId: signTransactionDto.chainId,
      });
      await pkpWallet.init();

      const signedTx = await pkpWallet.signTransaction(
        signTransactionDto.transaction,
      );
      return signedTx;
    } catch (error) {
      this.logger.error('Error in signing transaction', JSON.parse(error));
      throw new ServiceError('Transaction sign error', error);
    }
  }

  async sendUserTransactions(
    sendTransactionDto: TransactionsOperationDto,
  ): Promise<ethers.providers.TransactionReceipt> {
    try {
      await this.litClient.init();
      const pkpWallet = await this.validateSigner({
        wallet_address: sendTransactionDto.wallet_address,
        sessionKey: sendTransactionDto.sessionKey,
        chainId: sendTransactionDto.chainId,
      });
      await pkpWallet.init();
      const signedTx = await pkpWallet.signTransaction(
        sendTransactionDto.transaction,
      );
      const sentTx = await pkpWallet.sendTransaction(signedTx);
      const txnReceipt = await sentTx.wait();

      let tokenData = await this.litClient.getTransferEvent(
        sendTransactionDto.transaction.to,
        txnReceipt,
      );
      if (!tokenData?.value) {
        tokenData = {
          value: ethers.BigNumber.from(sendTransactionDto.transaction.value).toNumber(),
          address: ZERO_ADDRESS,
        };
      }

      const tokenInfo = await this.pkpTxnRepository.fetchTokenInfo(
        sendTransactionDto.chainId,
        tokenData.address,
      );

      const pkpTxn = txnReceipt as PkpTransactionData;
      pkpTxn.status = TransactionStatus[pkpTxn.status];

      await this.pkpTxnRepository.addPkpTxnDb(
        sendTransactionDto.transaction,
        sendTransactionDto.chainId,
        pkpTxn,
        tokenInfo,
      );
      return txnReceipt;
    } catch (error) {
      throw new ServiceError('Transaction send error', error);
    }
  }

  async getPkpTxns(address: string): Promise<PkpTransactionDocument[]> {
    try {
      const transactions: PkpTransactionDocument[] =
        await this.pkpTxnRepository.fetchTransaction(address);
      return transactions;
    } catch (error) {
      this.logger.error('Error in fetching pkp transactions ', error);
      throw new ServiceError('Error in fetching pkp transactions', error);
    }
  }

  async authenticate(
    getPubKeysDto: GetPubKeyDto,
    apiKeyHash: string,
    request: Request
  ): Promise<string> {
    try {
      const start_time = performance.now();
      await this.litClient.init();

      let authMethodResponse: AuthMethodResponseObject;

      const hasNativeAuth = await this.nativeAuthClient.hasNativeAuthEnabled(
       apiKeyHash,
       getPubKeysDto.provider,
      )

      if (hasNativeAuth) {
        authMethodResponse = await this.nativeAuthClient.verifyRequest(
          getPubKeysDto.provider,
          apiKeyHash,
          getPubKeysDto,
        )
      } else {
        authMethodResponse = await this.platformAuthClient.verifyRequest(
          apiKeyHash,
          getPubKeysDto.provider,
          getPubKeysDto,
          request
        );
      }

      let pkp: {
        pkpAddress: string;
        pkpPublicKey: string;
        tokenId: string;
        signingPermissions: PkpSigningPermissions;
      } = {
        pkpAddress: null,
        pkpPublicKey: null,
        tokenId: null,
        signingPermissions: null,
      };

      let accountId;
      const pkpObject = await this.litClient.getPubKeysFromAuthMethod(
        authMethodResponse,
        getPubKeysDto.chainId,
      );

      const userId = v4();
      if (pkpObject) {
        pkp['pkpPublicKey'] = pkpObject.publicKey;
        pkp['pkpAddress'] = ethers.utils.computeAddress(pkpObject.publicKey);
        pkp['tokenId'] = pkpObject.tokenId;
        pkp['signingPermissions'] = pkpObject.signingPermissions;
      } else {
        pkp = await this.litClient.claimKeyId(
          userId,
          authMethodResponse,
          getPubKeysDto.provider,
        );
        if (!pkp.pkpPublicKey.startsWith('0x'))
          pkp['pkpPublicKey'] = '0x' + pkp['pkpPublicKey'];
      }

      // checking for existing account
      // why do we need to again make a db call for this?
      const existingAccount = await this.accountsRepository.findOneByKey(
        'publicKey',
        pkp.pkpPublicKey,
      );
      accountId = existingAccount?._id;

      if (!existingAccount) {
        // creating user account
        const user: AccountUser = {
          ...authMethodResponse.user,
          primary_contact: authMethodResponse.primary_contact,
        };

        const authenticatedAccount: Accounts = {
          authProvider: getPubKeysDto.provider,
          litAuthId: undefined,
          pkpAddress: pkp.pkpAddress,
          publicKey: pkp.pkpPublicKey,
          user: user,
          keyId: generateLitKeyId(userId),
          userId,
          tokenId: pkp.tokenId,
          claimed: true,
          accountType: AccountType.TRADITIONAL,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };

        const dbResponse = await this.accountsRepository.createAccounts([
          authenticatedAccount,
        ]);
        accountId = dbResponse[0]._id;
      }

      const accessControlConditions: AccessControlConditions =
        request.body.accessControlConditions;

      // storing lit session in the db
      await this.getSessionKey(
        {
          provider: getPubKeysDto.provider,
          session_identifier: getPubKeysDto.session_identifier,
          authKey: null,
          chainId: getPubKeysDto.chainId ? getPubKeysDto.chainId : 1,
          expiration: getPubKeysDto.expiration
            ? getPubKeysDto.expiration
            : Date.now() + 1000 * 60 * 60 * 24,
          apiKeyId: apiKeyHash,
        },
        accountId,
        pkp.pkpPublicKey,
        pkp.signingPermissions,
        accessControlConditions,
        authMethodResponse,
      );
      const end_time = performance.now();
      this.logger.log('Time taken to authenticate: ', end_time - start_time);
      return ethers.utils.computeAddress(pkp.pkpPublicKey);
    } catch (error) {
      console.log(error);
      this.logger.error('Error in authenticating ', JSON.stringify(error));
      throw new ServiceError('Error in authenticating', error);
    }
  }

  async otp_auth_code(
    contact: string,
    mode: string,
  ): Promise<OTPsEmailLoginOrCreateResponse | Response> {
    if (mode == Provider.EMAIL) {
      return await this.stytchClient.sendPasscode(mode, contact);
    } else if (mode == Provider.SMS) {
      return await this.twilioAuthProvider.sendPasscode(mode, contact);
    } else {
      throw new ServiceError('Invalid mode for OTP');
    }
  }

  async pollSessionSigs(
    poll: PollSession,
    apiKeyhash: string,
  ): Promise<{ wallet_address: string; user: AccountUserData; key: string }> {
    const sessionDoc = await this.sessionsRepository.findOne({
      apiKeyId: apiKeyhash,
      session_identifier: poll.session_identifier,
    });
    if (sessionDoc) {
      if (sessionDoc.polled) {
        throw new ServiceError('Session already polled');
      }

      // 5 min limit to poll
      if (Date.now() > sessionDoc.createdAt + 300000) {
        await this.sessionsRepository.deleteSession(sessionDoc);
        throw new ServiceError('Session poll timeout');
      }

      const keys = await deconstructSessionSigs(sessionDoc);
      sessionDoc.sessionSigs = keys.serverSessionSig;

      if (!sessionDoc.accessControlConditions) {
        throw new ServiceError(
          `No access control conditions found for session ${sessionDoc.session_identifier}`,
        );
      }

      const jwtSignerKey = generateAuthConditions(
        sessionDoc.accessControlConditions,
      );

      const sessionKey: string = sign(
        {
          clientKey: keys.clientSessionKey,
        },
        jwtSignerKey,
        { expiresIn: '7d' },
      );

      await this.sessionsRepository.updateSession(sessionDoc);
      return {
        wallet_address: sessionDoc.wallet_address,
        user: sessionDoc.user,
        key: sessionKey,
      };
    } else {
      throw new ServiceError('No existing sessions');
    }
  }

  async addExternalWallet(
    walletData: ExternalWalletDto,
    apiKey: string,
  ): Promise<{ address: string; walletType: string }> {
    try {
      const timeStamp = new Date(walletData.message.match(TIMESTAMP_REGEX)[0]);
      const currentTime = new Date();

      if (currentTime.getTime() - timeStamp.getTime() > 60000) {
        this.logger.error('Signing window expired. Try again');
        throw new ServiceError('Signing window expired. Try again');
      }

      const message = walletData.message.split('\n');
      const nonce = message
        .filter((value) => {
          if (value.startsWith('Nonce')) return value;
        })[0]
        .slice(7);
      const existingNonce = await this.nonceRepository.findOneByKey(nonce);
      if (existingNonce) {
        this.logger.error('Nonce already used. Invalid message nonce');
        throw new ServiceError('Nonce already used. Invalid message nonce');
      }

      if (!ethers.utils.isAddress(walletData.address))
        throw new BadRequestException({
          message: MESSAGES.INVALID_ADDRESS,
          code: RESPONSE_CODES.BadRequest,
        });
      let signerAddress: string;
      try {
        signerAddress = ethers.utils.verifyMessage(
          walletData.message,
          walletData.signature,
        );
      } catch (error) {
        throw new BadRequestException({
          message: MESSAGES.INVALID_ADDRESS,
          code: RESPONSE_CODES.BadRequest,
        });
      }
      if (signerAddress.toLowerCase() !== walletData.address.toLowerCase()) {
        throw new BadRequestException({
          message: MESSAGES.INCORRECT_SIGNATURE,
          code: RESPONSE_CODES.BadRequest,
        });
      }
      const existingAccount = await this.accountsRepository.findExternalWallet({
        address: walletData.address,
        apiKeyId: apiKey,
      });
      if (existingAccount.length > 0) {
        await this.accountsRepository.updateExternalAccount(existingAccount[0]);
        return {
          address: existingAccount[0].address,
          walletType: existingAccount[0].walletType,
        };
      } else {
        await this.accountsRepository.createExternalWallet(
          walletData.address,
          apiKey,
          walletData.walletType,
        );
        await this.nonceRepository.addNonce(nonce);
        return {
          address: walletData.address,
          walletType: walletData.walletType,
        };
      }
    } catch (error) {
      throw new ServiceError('Error in creating wallet', error);
    }
  }

  async getTwitterRequestToken(state: string): Promise<string> {
    try {
      if (!state) {
        throw new BadRequestException('State not provided');
      }

      const response = await this.twitterClient.generateRequestToken(state);
      return response;
    } catch (error) {
      this.logger.error('Error in getting twitter request token', error);
      throw new ServiceError('Error in getting twitter request token', error);
    }
  }
}
