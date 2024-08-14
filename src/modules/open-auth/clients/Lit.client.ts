import {
  createSiweMessageWithCapacityDelegation,
  createSiweMessageWithRecaps,
  generateAuthSig,
  LitAbility,
  LitActionResource,
  LitPKPResource,
  LitRLIResource,
} from '@lit-protocol/auth-helpers';
import { AuthMethodScope } from '@lit-protocol/constants';
import {
  LitAuthClient,
  StytchOtpProvider,
} from '@lit-protocol/lit-auth-client';
import { LitNodeClient } from '@lit-protocol/lit-node-client';
import { LitContracts } from '@lit-protocol/contracts-sdk';
import { PKPEthersWallet } from '@lit-protocol/pkp-ethers';
import {
  AuthCallbackParams,
  AuthMethod,
  AuthSig,
  ExecuteJsResponse,
  SessionSigs,
  SessionSigsMap,
} from '@lit-protocol/types';
import { Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';
import { ChainId } from '../common/types';
import { ServiceError } from '../common/types';
import { CHAIN_PROVIDERS } from '../common/types';
import {
  customAuthAction,
  customAuthMethod,
} from '../common/helpers';
import { pkpHelperAbi } from '../../../abis/PKPHelperContract.abi';
import { pkpNftAbi } from '../../../abis/PKPNftContract.abi';
import { pkpPermissionsAbi } from '../../../abis/PKPPermissionsContract.abi';
import { abi } from '../../../abis/TransferEvent.abi';
import {
  LIT_ACTION_1_CID,
  LIT_API_KEY,
  LIT_CLAIM_KEY_ACTION_CID,
  LIT_CLIENT_NETWORK,
  LIT_CLIENT_TIMEOUT,
  LIT_CONTROLLER_PRIVATE_KEY,
  LIT_CREDITS_TOKENID,
  LIT_CUSTOM_AUTH_TYPE_ID,
  pkpHelper_CONTRACT_ADDRESS,
  pkpNft_CONTRACT_ADDRESS,
  pkpPermissions_CONTRACT_ADDRESS,
  STYTCH_PROJECT_ID, YELLOWSTONE_CHRONICLE_RPC_URL
} from "../common/constants";
import {
  AuthMethodResponseObject,
  PKPMintPayload,
  PkpSigningPermissions,
  Provider,
} from '../common/types';

@Injectable()
export class LitClient {
  private readonly logger = new Logger(LitClient.name);
  private readonly litNodeClient = new LitNodeClient({
    litNetwork: LIT_CLIENT_NETWORK,
    debug: false,
  });

  private readonly litAuthClient = new LitAuthClient({
    litRelayConfig: {
      relayApiKey: LIT_API_KEY,
    },
    litNodeClient: this.litNodeClient,
  });

  private readonly litContractClient: LitContracts;

  private readonly provider: ethers.providers.Provider;
  private readonly controllerWallet: ethers.Wallet;
  private readonly pkpContracts: { [key: string]: ethers.Contract } = {};

  constructor() {
    this.provider = new ethers.providers.JsonRpcProvider(YELLOWSTONE_CHRONICLE_RPC_URL);
    this.controllerWallet = new ethers.Wallet(
      LIT_CONTROLLER_PRIVATE_KEY,
      this.provider,
    );
    this.pkpContracts['pkpNFTContract'] = new ethers.Contract(
      pkpNft_CONTRACT_ADDRESS[LIT_CLIENT_NETWORK],
      pkpNftAbi,
      this.controllerWallet,
    );
    this.pkpContracts['pkpHelperContract'] = new ethers.Contract(
      pkpHelper_CONTRACT_ADDRESS[LIT_CLIENT_NETWORK],
      pkpHelperAbi,
      this.controllerWallet,
    );
    this.pkpContracts['pkpPermissionsContract'] = new ethers.Contract(
      pkpPermissions_CONTRACT_ADDRESS[LIT_CLIENT_NETWORK],
      pkpPermissionsAbi,
      this.controllerWallet,
    );
    this.litContractClient = new LitContracts({
      signer: this.controllerWallet,
      network: LIT_CLIENT_NETWORK,
    });
  }

  async init(): Promise<void> {
    if (!this.litNodeClient.ready) {
      await this.litNodeClient.connect();
      await this.litContractClient.connect();
    }
  }

  // Here to close the connection to the LitNodeClient on intervals to save bandwidth in the long run
  // This function must be called only once by open auth when initializing, or can cause memory leak
  close(): void {
    setInterval(async () => {
      await this.litNodeClient.disconnect();
    }, LIT_CLIENT_TIMEOUT);
  }

  async generateProviderAuthMethod(
    sessionJwt: string,
  ): Promise<{ authMethod: AuthMethod; authId: string }> {
    try {
      const stytchAuthProvider = new StytchOtpProvider(
        {
          litNodeClient: this.litNodeClient,
          relay: this.litAuthClient.relay,
        },
        {
          appId: STYTCH_PROJECT_ID,
        },
      );
      const authMethod = await stytchAuthProvider.authenticate({
        accessToken: sessionJwt,
      });
      const authId = await stytchAuthProvider.getAuthMethodId(authMethod);
      return { authMethod, authId };
    } catch (error) {
      throw new ServiceError('Stytchprovider authenticate error', error);
    }
  }

  async getCustomAuthSessionSigs(
    authMethodObject: { id: string; type: number },
    pkpPublicKey: string,
    chainId: number,
  ): Promise<SessionSigs> {
    try {
      const capacityDelegationAuthSig = await this.createDelegationAuthSig(
        [ethers.utils.computeAddress(pkpPublicKey)],
        chainId,
        new Date(Date.now() + 1000 * 60 * 60),
      );

      return await this.litNodeClient.getLitActionSessionSigs({
        pkpPublicKey: pkpPublicKey,
        resourceAbilityRequests: [
          { resource: new LitPKPResource('*'), ability: LitAbility.PKPSigning },
          {
            resource: new LitActionResource('*'),
            ability: LitAbility.LitActionExecution,
          },
          {
            resource: new LitRLIResource(LIT_CREDITS_TOKENID),
            ability: LitAbility.RateLimitIncreaseAuth,
          },
        ],
        litActionIpfsId: LIT_ACTION_1_CID,
        jsParams: {
          pkpPublicKey: pkpPublicKey,
          customAuthMethod: {
            authMethodType: `0x${authMethodObject.type.toString(16)}`,
            authMethodId: `0x${Buffer.from(
              new TextEncoder().encode(authMethodObject.id),
            ).toString('hex')}`,
          },
          sigName: 'custom-auth-sig',
        },
        capabilityAuthSigs: [capacityDelegationAuthSig],
        chain: ChainId[chainId],
      });
    } catch (error) {
      throw new ServiceError(
        'Error in getting custom auth session sigs',
        error,
      );
    }
  }

  async getControllerSessionSig(
    chainId = 11155111,
    authSig?: AuthSig,
  ): Promise<SessionSigsMap> {
    try {
      const resourceAbilities = [
        {
          resource: new LitPKPResource('*'),
          ability: LitAbility.PKPSigning,
        },
        {
          resource: new LitActionResource('*'),
          ability: LitAbility.LitActionExecution,
        },
        {
          resource: new LitRLIResource(LIT_CREDITS_TOKENID),
          ability: LitAbility.RateLimitIncreaseAuth,
        },
      ];

      const authNeededCallback = async (
        params: AuthCallbackParams,
      ): Promise<AuthSig> => {
        try {
          if (authSig) {
            return authSig;
          }

          if (!params.uri) {
            throw new Error('URI is required');
          }

          if (!params.expiration) {
            throw new Error('Expiration is required');
          }

          if (!params.resourceAbilityRequests) {
            throw new Error(`resourceAbilityRequests is required`);
          }

          const latestBlockHash = this.litNodeClient.latestBlockhash;

          const toSign = await createSiweMessageWithRecaps({
            uri: params.uri,
            chainId: chainId,
            expiration: params.expiration,
            resources: params.resourceAbilityRequests,
            walletAddress: this.controllerWallet.address,
            nonce: latestBlockHash,
            litNodeClient: this.litNodeClient,
          });

          return await generateAuthSig({
            signer: this.controllerWallet,
            toSign,
          });
        } catch (error) {
          this.logger.error(`Error in generation auth sig for session sigs`);
          this.logger.error(error);
          throw new Error(
            `Error in generation auth sig for session sigs, ${error}`,
          );
        }
      };

      const sessionSigs = await this.litNodeClient.getSessionSigs({
        chain: ChainId[chainId],
        resourceAbilityRequests: resourceAbilities,
        authNeededCallback: authNeededCallback,
      });

      return sessionSigs;
    } catch (error) {
      this.logger.error(
        `Error in getting controller session sig, ${JSON.stringify(error)}`,
      );
      throw new ServiceError(
        `Error in getting controller session sig, ${error.message}`,
      );
    }
  }

  async callLitAction(
    lit_action_cid: string,
    params: Record<string, unknown>,
    chainId = 11155111,
  ): Promise<ExecuteJsResponse> {
    const sessionSigs = await this.getControllerSessionSig(chainId);
    const childCorrelationId = Math.random().toString(16).slice(2);
    return await this.litNodeClient.executeJs({
      sessionSigs: sessionSigs,
      ipfsId: lit_action_cid,
      jsParams: {
        ...params,
        sessionSigs: sessionSigs,
        CHILD_CORRELATION_ID: childCorrelationId,
      },
    });
  }

  async claimKeyId(
    userId: string,
    authMethodObj: AuthMethodResponseObject,
    provider: string,
  ): Promise<{
    pkpAddress: string;
    pkpPublicKey: string;
    tokenId: string;
    signingPermissions: PkpSigningPermissions;
  }> {
    try {
      this.logger.log('Mining a new PKP');
      const start_time = performance.now();
      const permittedLitAction = customAuthAction(LIT_ACTION_1_CID);

      let mintPayload: PKPMintPayload;
      switch (provider) {
        case Provider.FARCASTER:
        case Provider.X:
        case Provider.SMS:
        case Provider.TELEGRAM: {
          mintPayload = {
            permittedIpfsCIDs: [permittedLitAction],
            permittedIpfsCIDScopes: [[AuthMethodScope.SignAnything]],
            permittedAuthMethodTypes: [authMethodObj.authMethod.authMethodType],
            permittedAuthMethodIds: [authMethodObj.authId],
            permittedAuthMethodPubkeys: [`0x`],
            permittedAuthMethodScopes: [[AuthMethodScope.SignAnything]],
          };
          break;
        }
        case Provider.DISCORD:
        case Provider.GOOGLE:
        case Provider.EMAIL: {
          const customAuth = customAuthMethod(authMethodObj.primary_contact);
          mintPayload = {
            permittedIpfsCIDs: [permittedLitAction],
            permittedIpfsCIDScopes: [[AuthMethodScope.SignAnything]],
            permittedAuthMethodTypes: [
              authMethodObj.authMethod.authMethodType,
              customAuth.authMethodType,
            ],
            permittedAuthMethodIds: [authMethodObj.authId, customAuth.id],
            permittedAuthMethodPubkeys: [`0x`, `0x`],
            permittedAuthMethodScopes: [
              [AuthMethodScope.SignAnything],
              [AuthMethodScope.SignAnything],
            ],
          };
          break;
        }
        default: {
          throw new ServiceError(`Invalid provider to mint PKP ${provider}`);
          break;
        }
      }

      const res = await this.litNodeClient.executeJs({
        sessionSigs: await this.getControllerSessionSig(),
        ipfsId: LIT_CLAIM_KEY_ACTION_CID,
        jsParams: {
          userId: userId,
        },
      });

      const cost = await this.pkpContracts['pkpNFTContract'].mintCost();
      const tx = await this.pkpContracts[
        'pkpHelperContract'
      ].claimAndMintNextAndAddAuthMethods(
        {
          keyType: 2,
          derivedKeyId: `0x${res.claims[userId].derivedKeyId}`,
          signatures: res.claims[userId].signatures,
        },
        {
          keyType: 2,
          permittedIpfsCIDs: mintPayload.permittedIpfsCIDs,
          permittedIpfsCIDScopes: mintPayload.permittedIpfsCIDScopes,
          permittedAddresses: [],
          permittedAddressScopes: [],
          permittedAuthMethodTypes: mintPayload.permittedAuthMethodTypes,
          permittedAuthMethodIds: mintPayload.permittedAuthMethodIds,
          permittedAuthMethodPubkeys: mintPayload.permittedAuthMethodPubkeys,
          permittedAuthMethodScopes: mintPayload.permittedAuthMethodScopes,
          addPkpEthAddressAsPermittedAddress: true,
          sendPkpToItself: true,
        },
        {
          value: cost,
        },
      );

      const tx_receipt = await tx.wait();
      const events =
        'events' in tx_receipt ? tx_receipt.events : tx_receipt.logs;
      const tokenId = events[0].topics[1];
      const publicKey = await this.pkpContracts['pkpNFTContract'].getPubkey(
        tokenId,
      );
      const pkpAddress = ethers.utils.computeAddress(publicKey);
      const signingPermissions = await this.checkAuthPermission(
        tokenId,
        authMethodObj,
      );

      const end_time = performance.now();
      this.logger.log(`Time taken to claim PKP ${end_time - start_time} ms`);
      return {
        pkpAddress: pkpAddress,
        pkpPublicKey: publicKey,
        tokenId: tokenId,
        signingPermissions: signingPermissions,
      };
    } catch (error) {
      this.logger.error('Lit claim pkp error ', error.message);
      throw new ServiceError('Lit Claim PKP error', error.message);
    }
  }

  async addPkpAuthMethods(
    pkpPublicAddress: string,
    tokenId: string,
    customAuth: {
      id: string;
      authMethodType: number;
    },
    authMethodObj: AuthMethodResponseObject,
    signingPermissions: PkpSigningPermissions,
    chainId: number,
  ): Promise<boolean> {
    if (!signingPermissions.litAction && !signingPermissions.stytch) {
      return false;
    }
    try {
      let sessionSigs: SessionSigs;
      if (
        !signingPermissions.stytch &&
        authMethodObj.authMethod.authMethodType == 9
      ) {
        return false;
      } else if (
        !signingPermissions.litAction &&
        authMethodObj.authMethod.authMethodType == LIT_CUSTOM_AUTH_TYPE_ID
      ) {
        return false;
      }

      let pkpWalletInstance: PKPEthersWallet;
      if (sessionSigs) {
        pkpWalletInstance = await this.getPKPEtherWallet(
          pkpPublicAddress,
          sessionSigs,
          chainId,
        );
        await pkpWalletInstance.init();
      }

      if (
        (!signingPermissions.litAction || !signingPermissions.stytch) &&
        !signingPermissions.customAuth
      ) {
        return false;
      }

      if (!signingPermissions.customAuth) {
        const transactionRequest = {
          to: pkpPermissions_CONTRACT_ADDRESS[LIT_CLIENT_NETWORK],
          from: pkpWalletInstance.address,
          data: this.pkpContracts[
            'pkpPermissionsContract'
          ].interface.encodeFunctionData('addPermittedAuthMethod', [
            BigInt(tokenId),
            {
              authMethodType: customAuth.authMethodType,
              id: customAuth.id,
              userPubKey: '0x',
            },
            ['0x'],
          ]),
        };

        const tx = await pkpWalletInstance.sendTransaction(transactionRequest);
        const receipt = await tx.wait();
        this.logger.log('Added Custom auth ', receipt);
      }

      return true;
    } catch (error) {
      this.logger.error(
        `Error in signing permissions for custom auth ${error.toString()}`,
      );
      throw new Error(`Error in signing permissions for custom auth ${error}`);
    }
  }

  async getPubKeysFromAuthMethod(
    authMethodObj: AuthMethodResponseObject,
    chainId: number,
  ): Promise<{
    publicKey: string;
    tokenId: string;
    signingPermissions: PkpSigningPermissions;
  } | null> {
    let start_time, end_time;
    try {
      const customAuth = customAuthMethod(authMethodObj.primary_contact);

      start_time = performance.now();
      let tokenIds = await this.pkpContracts[
        'pkpPermissionsContract'
      ].getTokenIdsForAuthMethod(customAuth.authMethodType, customAuth.id);

      let addCustomAuth = false;
      if (tokenIds.length === 0) {
        tokenIds = await this.pkpContracts[
          'pkpPermissionsContract'
        ].getTokenIdsForAuthMethod(
          authMethodObj.authMethod.authMethodType,
          authMethodObj.authId,
        );
        addCustomAuth = true;
      }
      end_time = performance.now();
      this.logger.log(
        `Time taken to get token ids for auth method ${end_time - start_time}`,
      );

      this.logger.log('tokenIds', tokenIds);
      if (tokenIds.length > 0) {
        // Fetch public keys for all tokenIds and return the wallet with most balance
        start_time = performance.now();
        const publicKeys = await Promise.all(
          tokenIds.map(async (tokenId: string) => {
            return this.pkpContracts['pkpNFTContract'].getPubkey(tokenId);
          }),
        );
        await Promise.all(publicKeys);
        end_time = performance.now();
        this.logger.log(
          `Time taken to get public keys for token ids ${
            end_time - start_time
          }`,
        );

        const tokenId = tokenIds[tokenIds.length - 1];
        const publicKey = publicKeys[publicKeys.length - 1];

        const signingPermissions = await this.checkAuthPermission(
          tokenId,
          authMethodObj,
        );

        if (
          !(await this.addPkpAuthMethods(
            publicKey,
            tokenId,
            customAuth,
            authMethodObj,
            signingPermissions,
            chainId,
          ))
        ) {
          return null;
        }

        return {
          publicKey,
          tokenId,
          signingPermissions,
        };
      }
      return null;
    } catch (error) {
      this.logger.error(error);
      throw new ServiceError('Error in fetching lit pkp public keys', error);
    }
  }

  async getSessionSigs(
    authMethod: AuthMethod,
    publicKey: string,
    chainId: number,
    expiration: Date,
  ): Promise<SessionSigs> {
    const start_time = performance.now();
    try {
      const resourceAbilities = [
        {
          resource: new LitActionResource('*'),
          ability: LitAbility.LitActionExecution,
        },
        {
          resource: new LitPKPResource('*'),
          ability: LitAbility.PKPSigning,
        },
        {
          resource: new LitRLIResource(LIT_CREDITS_TOKENID),
          ability: LitAbility.RateLimitIncreaseAuth,
        },
      ];

      const sessionKeyPair = this.litNodeClient.getSessionKey();

      const capacityDelegationAuthSig = await this.createDelegationAuthSig(
        [ethers.utils.computeAddress(publicKey)],
        chainId,
        new Date(Date.now() + 1000 * 60 * 60),
      );

      const authNeededCallback = async (
        params: AuthCallbackParams,
      ): Promise<AuthSig> => {
        try {
          const response = await this.litNodeClient.signSessionKey({
            sessionKey: sessionKeyPair,
            statement: params.statement,
            authMethods: [authMethod],
            pkpPublicKey: publicKey,
            expiration: params.expiration,
            resources: params.resources,
            resourceAbilityRequests: params.resourceAbilityRequests,
            chainId: chainId,
          });
          return response.authSig;
        } catch (error) {
          this.logger.error(
            `Error in generation auth sig for session sigs, ${error}`,
          );
          throw new ServiceError(
            `Error in generation auth sig for session sigs, ${error}`,
          );
        }
      };

      const sessionSigs = await this.litNodeClient.getSessionSigs({
        chain: ChainId[chainId],
        expiration: expiration.toISOString(),
        resourceAbilityRequests: resourceAbilities,
        sessionKey: sessionKeyPair,
        authNeededCallback,
        capabilityAuthSigs: [capacityDelegationAuthSig],
      });
      const end_time = performance.now();
      this.logger.log(
        `Time taken to get session sigs ${end_time - start_time}`,
      );
      return sessionSigs;
    } catch (error) {
      this.logger.error('Error in getting session sigs', error);
      throw new ServiceError('Error in getting session sigs', error);
    }
  }

  async getPKPEtherWallet(
    PKP_PUBLIC_KEY: string,
    sessionSigs: SessionSigs,
    chainId: number,
  ): Promise<PKPEthersWallet> {
    try {
      const pkpWallet = new PKPEthersWallet({
        pkpPubKey: PKP_PUBLIC_KEY,
        rpc: CHAIN_PROVIDERS[chainId],
        controllerSessionSigs: sessionSigs,
        litNodeClient: this.litNodeClient,
      });
      return pkpWallet;
    } catch (error) {
      throw new ServiceError('Error in generating ether wallet', error);
    }
  }

  async checkAuthPermission(
    tokenId: string,
    authMethodObj: AuthMethodResponseObject,
  ): Promise<PkpSigningPermissions> {
    const litActionAuth = customAuthAction(LIT_ACTION_1_CID);
    const customAuth = customAuthMethod(authMethodObj.primary_contact);

    const permissions: PkpSigningPermissions = {
      litAction: false, // signing
      customAuth: false, // always true
      stytch: false, // signing
    };

    permissions.litAction = await this.pkpContracts[
      'pkpPermissionsContract'
    ].isPermittedAction(BigInt(tokenId), litActionAuth);

    permissions.customAuth = await this.pkpContracts[
      'pkpPermissionsContract'
    ].isPermittedAuthMethod(
      BigInt(tokenId),
      customAuth.authMethodType,
      customAuth.id,
    );

    if (authMethodObj.authMethod.authMethodType == 9) {
      permissions.stytch = await this.pkpContracts[
        'pkpPermissionsContract'
      ].isPermittedAuthMethod(BigInt(tokenId), 9, authMethodObj.authId);
    }

    this.logger.log(permissions);

    return permissions;
  }

  async getTransferEvent(
    contract_address: string,
    txn: ethers.providers.TransactionReceipt,
  ): Promise<{ value: number; address: string }> {
    const contract = new ethers.Contract(contract_address, abi, this.provider);
    const events = txn.logs.map((log) => {
      const data = contract.interface.parseLog(log);
      const value = data?.args[2];
      return { value, address: log?.address };
    });
    return events[0];
  }

  async createDelegationAuthSig(
    delegateeAddresses: string[],
    chainId: number,
    expiration: Date,
  ): Promise<AuthSig> {
    try {
      const nonce = this.litNodeClient.latestBlockhash;
      const address = await this.controllerWallet.getAddress();
      const siweMessage = await createSiweMessageWithCapacityDelegation({
        uri: 'lit:capability:delegation',
        litNodeClient: this.litNodeClient,
        walletAddress: address,
        nonce: nonce,
        uses: '1000',
        expiration: new Date(expiration).toISOString(),
        domain: 'localhost',
        delegateeAddresses: delegateeAddresses,
        capacityTokenId: LIT_CREDITS_TOKENID,
        chainId: chainId,
      });

      return await generateAuthSig({
        signer: this.controllerWallet,
        toSign: siweMessage,
      });
    } catch (error) {
      this.logger.error(
        `Error in creating delegation auth sig ${error.message}`,
      );
      throw new ServiceError(
        `Error in creating delegation auth sig ${error.message}`,
      );
    }
  }
}
