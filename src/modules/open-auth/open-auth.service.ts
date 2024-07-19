import { PKPEthersWallet } from '@lit-protocol/pkp-ethers';
import { SessionSigs } from '@lit-protocol/types';
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';
import { OTPsEmailLoginOrCreateResponse } from 'stytch';
import { v4 } from 'uuid';
import { ServiceError } from './utils/types.interfaces';
import {
  customAuthMethod,
  deconstructSessionSigs,
  generateLitKeyId,
  reconstructSessionSigs,
} from './utils/helper-functions';
import { MESSAGES, RESPONSE_CODES } from './utils/response.messages';
import { FarcasterClient } from './client/Farcaster.client';
import { TwitterClient } from './client/Twitter.client';
import { TelegramClient } from './client/Telegram.client';
import { LitClient } from './client/Lit.client';
import { StytchClient } from './client/Stytch.client';
import {
  ClaimAccountDto,
  ExternalWalletDto,
  GetPubKeyDto,
  ResolveAccountDto,
} from './dto/Accounts.dto';
import { PollSession, SessionKeyDto } from './dto/Sessions.dto';
import {
  SignerDto,
  SignMessageDto,
  TransactionsOperationDto,
} from './dto/Transactions.dto';
import { Accounts, AccountUser } from './entities/Accounts.entity';
import { PkpTransactionDocument } from './entities/PkpTransaction.entity';
import { SessionsDocument } from './entities/Sessions.entity';
import { AccountsRepository } from './repositories/accounts.repository';
import { PkpTransactionsRepository } from './repositories/pkptransactions.repository';
import { SessionsRepository } from './repositories/sessions.repository';
import {
  TIMESTAMP_REGEX,
  TWILIO_ACCOUNT_SECRET_AUTH_TOKEN,
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_BASE_URL,
  TWILIO_SERVICE_ID, ZERO_ADDRESS,
} from './utils/constants';
import {
  AccountType,
  AccountUserData,
  AuthMethodResponseObject,
  PkpSigningPermissions,
  PkpTransactionData,
  Provider,
  TransactionStatus,
} from './utils/types.interfaces';
import { NonceUsedRepository } from './repositories/nonce.repository';

@Injectable()
export class OpenAuthService {
  private readonly logger = new Logger(OpenAuthService.name);
  constructor(
    private readonly litClient: LitClient,
    private readonly stytchClient: StytchClient,
    private readonly farcasterClient: FarcasterClient,
    private readonly twitterClient: TwitterClient,
    private readonly telegramClient: TelegramClient,
    private readonly accountsRepository: AccountsRepository,
    private readonly sessionsRepository: SessionsRepository,
    private readonly pkpTxnRepository: PkpTransactionsRepository,
    private readonly nonceRepository: NonceUsedRepository,
  ) {
    this.litClient.close();
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

  async resolveAccount(
    resolveAccount: ResolveAccountDto[],
  ): Promise<string[] | null> {
    await this.litClient.init();
    const pkpAddresses: string[] = [];
    const accounts: Accounts[] = [];
    for (const accountdto of resolveAccount) {
      if (!accountdto.provider) continue;
      try {
        const primary_contact = accountdto.primary_contact;

        const existingAccount = await this.accountsRepository.findOneByKey(
          'user.primary_contact',
          primary_contact,
        );
        if (existingAccount && existingAccount.pkpAddress) {
          pkpAddresses.push(existingAccount.pkpAddress);
          continue;
        }
        const userId = v4();
        const keyId = generateLitKeyId(userId);
        const cfaPKPResponse = await this.litClient.computeCFAFromUserID(keyId);

        const resolvedUser: AccountUser = {
          first_name: null,
          last_name: null,
          middle_name: null,
          primary_contact: primary_contact,
        };

        const resolvedAccount: Accounts = {
          authProvider: accountdto.provider,
          litAuthId: undefined,
          pkpAddress: cfaPKPResponse.ethAddress,
          publicKey: `0x${cfaPKPResponse.publicKey}`,
          user: resolvedUser,
          keyId: cfaPKPResponse.keyId,
          userId,
          tokenId: null,
          claimed: false,
          accountType: AccountType.RESOLVED,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };
        pkpAddresses.push(cfaPKPResponse.ethAddress);
        accounts.push(resolvedAccount);
      } catch (error) {
        pkpAddresses.push('error');
        continue;
      }
    }
    if (accounts.length > 0) {
      await this.accountsRepository.createAccounts(accounts);
    }
    return pkpAddresses;
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
    authMethodObject?: AuthMethodResponseObject,
  ): Promise<void> {
    await this.litClient.init();
    const existingSession = await this.sessionsRepository.findOne({
      session_identifier: sessionKeyDto.session_identifier,
      // can cause duplicate key error in case of same session identifier in case if session was never polled
      expiresAt: { $gt: new Date() },
    });
    if (existingSession) {
      this.logger.log(existingSession);
      return;
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

    await this.sessionsRepository.createSession(
      sessionSig,
      sessionUser,
      new Date(sessionKeyDto.expiration),
      userAccountId,
      sessionKeyDto.session_identifier,
      sessionKeyDto.apiKeyId,
      ethers.utils.computeAddress(pkpPublicAddress),
    );
    return;
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

      let sessionSig: SessionSigs;
      if (sessionSigDocument) {
        if (sessionSigDocument.expiresAt < new Date()) {
          throw new ServiceError('Session expired');
        }

        sessionSig = reconstructSessionSigs(
          signerDto.sessionKey,
          sessionSigDocument.sessionSigs,
        );
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
  ): Promise<string> {
    try {
      const start_time = performance.now();
      await this.litClient.init();

      //shift this outside this function
      let authMethodResponse: AuthMethodResponseObject = {
        authMethod: {
          authMethodType: null,
          accessToken: null,
        },
        authId: null,
        primary_contact: null,
        user: null,
        profile_picture_url: null,
      };

      switch (getPubKeysDto.provider) {
        case Provider.EMAIL: {
          if (getPubKeysDto.code && getPubKeysDto.method_id) {
            const sessionResponse = await this.stytchClient.validateEmailOTP(
              getPubKeysDto.code,
              getPubKeysDto.method_id,
            );
            authMethodResponse =
              await this.litClient.generateProviderAuthMethod(
                sessionResponse.session_jwt,
              );
            authMethodResponse['primary_contact'] =
              sessionResponse?.user?.emails[0]?.email;
            authMethodResponse['user'] = { ...sessionResponse?.user?.name };
          } else {
            throw new ServiceError('Method Id or email OTP not passed');
          }
          break;
        }
        case Provider.SMS: {
          if (getPubKeysDto.code && getPubKeysDto.phone_number) {
            const smsRes = await this.validateSMS(
              getPubKeysDto.code,
              getPubKeysDto.phone_number,
            );
            if (smsRes) {
              const customAuth = customAuthMethod(getPubKeysDto.phone_number);
              authMethodResponse = {
                primary_contact: getPubKeysDto.phone_number,
                authMethod: {
                  authMethodType: customAuth.authMethodType,
                  accessToken: null,
                },
                authId: customAuth.id,
              };
            } else {
              throw new ServiceError(
                'SMS authentication failed. OTP Validation Unsuccessful',
              );
            }
          } else {
            throw new ServiceError(
              'SMS authentication failed: OTP or Phone number not passed',
            );
          }
          break;
        }
        case Provider.X: {
          const xAuthSession = getPubKeysDto.x_session;
          if (!xAuthSession) {
            throw new BadRequestException(
              'X authentication failed: X Auth data not passed',
            );
          }

          if (!xAuthSession.oauth_token) {
            throw new BadRequestException(
              'X authentication failed: X Auth token not passed',
            );
          }

          if (!xAuthSession.oauth_verifier) {
            throw new BadRequestException(
              'X authentication failed: X Auth verifier not passed',
            );
          }

          const xAuthResponse = await this.twitterClient.generateAccessToken(
            xAuthSession.oauth_token,
            xAuthSession.oauth_verifier,
          );

          const authHeader: string = this.twitterClient.generateXAuthHeader(
            xAuthResponse.oauth_token,
            xAuthResponse.oauth_token_secret,
            'GET',
            { include_email: true },
          );

          const result = await this.twitterClient.getTwitterAccountCredentials(
            authHeader,
          );

          const customAuth = customAuthMethod(result.email);
          authMethodResponse = {
            primary_contact: result.email,
            profile_picture_url: result.profile_picture_url,
            authMethod: {
              authMethodType: customAuth.authMethodType,
              accessToken: null,
            },
            authId: customAuth.id,
            user: {
              first_name: result.name,
            },
          };
          break;
        }
        case Provider.FARCASTER: {
          if (getPubKeysDto.farcaster_session) {
            const farcasterRes = await this.farcasterClient.verifySignature(
              getPubKeysDto.farcaster_session,
            );
            if (farcasterRes && farcasterRes.success && farcasterRes.fid) {
              const customAuth = customAuthMethod(farcasterRes.fid);
              authMethodResponse = {
                primary_contact: farcasterRes.fid,
                authMethod: {
                  authMethodType: customAuth.authMethodType,
                  accessToken: null,
                },
                authId: customAuth.id,
              };
            } else {
              throw new ServiceError('Farcaster authentication failed');
            }
          } else {
            throw new ServiceError('Farcaster session data not passed');
          }
          break;
        }
        case Provider.DISCORD:
        case Provider.GOOGLE: {
          //oauth
          authMethodResponse = await this.authenticateLitSession(
            getPubKeysDto.authKey,
            getPubKeysDto.provider,
          );
          break;
        }
        case Provider.TELEGRAM: {
          try {
            if (!getPubKeysDto.telegram_session) {
              throw new ServiceError('Telegram auth data not passed');
            }
            if (
              !getPubKeysDto.telegram_session.id ||
              !getPubKeysDto.telegram_session.hash ||
              !getPubKeysDto.telegram_session.auth_date
            ) {
              throw new ServiceError(
                'Missing required parameters for Telegram auth, missing id or hash or aut_date',
              );
            }

            const telegramSession = getPubKeysDto.telegram_session;
            const success = await this.telegramClient.verify(telegramSession);
            if (!success) {
              throw new ServiceError('Telegram auth verification failed');
            }

            const customAuth = customAuthMethod(telegramSession.id);
            authMethodResponse = {
              primary_contact: telegramSession.id,
              authMethod: {
                authMethodType: customAuth.authMethodType,
                accessToken: null,
              },
              authId: customAuth.id,
            };

            if (telegramSession.photo_url) {
              authMethodResponse.profile_picture_url =
                telegramSession.photo_url;
              authMethodResponse.user = {
                profile_picture_url: telegramSession.photo_url,
              };
            }

            if (telegramSession.first_name) {
              authMethodResponse.user = {
                ...authMethodResponse.user,
                first_name: telegramSession.first_name,
              };
            }

            if (telegramSession.last_name) {
              authMethodResponse.user = {
                ...authMethodResponse.user,
                last_name: telegramSession.last_name,
              };
            }

            if (telegramSession.username) {
              authMethodResponse.user = {
                ...authMethodResponse.user,
                username: telegramSession.username,
              };
            }
          } catch (error) {
            throw new ServiceError('Error in authenticating Telegram', error);
          }

          break;
        }
        default:
          throw new ServiceError(
            'Authentication failed: Invalid Provider option',
          );
          break;
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
        authMethodResponse,
      );
      const end_time = performance.now();
      this.logger.log('Time taken to authenticate: ', end_time - start_time);
      return ethers.utils.computeAddress(pkp.pkpPublicKey);
    } catch (error) {
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
      try {
        const twilio_auth_token = btoa(
          `${TWILIO_ACCOUNT_SID}:${TWILIO_ACCOUNT_SECRET_AUTH_TOKEN}`,
        );
        const headers = {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${twilio_auth_token}`,
        };
        const data = {
          To: contact,
          Channel: 'sms',
        };
        const twilioResponse = await fetch(
          `${TWILIO_AUTH_BASE_URL}Services/${TWILIO_SERVICE_ID}/Verifications`,
          {
            method: 'POST',
            body: new URLSearchParams(data),
            headers: headers,
          },
        );
        this.logger.log('twilio response ', await twilioResponse.json());
        return twilioResponse;
      } catch (error) {
        this.logger.error('Twilio OTP error ', error);
        throw new ServiceError('Twilio OTP error ', error);
      }
    } else {
      throw new ServiceError('Invalid mode for OTP');
    }
  }

  async validateSMS(code: string, to: string): Promise<boolean> {
    try {
      const twilio_auth_token = btoa(
        `${TWILIO_ACCOUNT_SID}:${TWILIO_ACCOUNT_SECRET_AUTH_TOKEN}`,
      );
      const auth_url = `${TWILIO_AUTH_BASE_URL}Services/${TWILIO_SERVICE_ID}/VerificationCheck`;

      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${twilio_auth_token}`,
      };

      const sms_authenticate = await fetch(auth_url, {
        method: 'POST',
        body: new URLSearchParams({ Code: code, To: to }),
        headers: headers,
      });

      const res = await sms_authenticate.json();
      if (res.status == 'approved') {
        return true;
      }
      return false;
    } catch (error) {
      this.logger.error('Error in validating sms ', error);
      throw new ServiceError(error);
    }
  }

  async pollSessionSigs(
    poll: PollSession,
    apiKeyhash: string,
  ): Promise<{ wallet_address: string; user: AccountUserData; key: string }> {
    const sessionSigs = await this.sessionsRepository.findOne({
      apiKeyId: apiKeyhash,
      session_identifier: poll.session_identifier,
    });
    if (sessionSigs) {
      if (sessionSigs.polled) {
        throw new ServiceError('Session already polled');
      }

      // 5 min limit to poll
      if (Date.now() > sessionSigs.createdAt + 300000) {
        await this.sessionsRepository.deleteSession(sessionSigs);
        throw new ServiceError('Session poll timeout');
      }

      const keys = await deconstructSessionSigs(sessionSigs);
      await this.sessionsRepository.updateSession(keys.serverSessionSig);
      return {
        wallet_address: sessionSigs.wallet_address,
        user: sessionSigs.user,
        key: keys.clientSessionKey,
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
