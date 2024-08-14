import { AuthMethod } from '@lit-protocol/types';
import {
  ARBITRUM_GOERLI_RPC_URL,
  ARBITRUM_RPC_URL,
  ARBITRUM_SEPOLIA_RPC_URL, AVALANCHE_FUJI_RPC_URL, AVALANCHE_MAINNET_RPC_URL,
  BASE_MAINNET_RPC_URL,
  BASE_TESTNET_RPC_URL,
  BSC_MAINNET_RPC_URL,
  BSC_TESTNET_RPC_URL,
  ETH_GOERLI_RPC_URL,
  ETH_MAINNET_RPC_URL,
  ETH_SEPOLIA_RPC_URL, LINEA_MAINNET_RPC_URL, LINEA_TESTNET_RPC_URL,
  OPTIMISM_MAINNET_RPC_URL,
  POLYGON_AMOY_RPC_URL,
  POLYGON_MAINNET_RPC_URL,
  POLYGON_ZKEVM_MAINNET_RPC_URL
} from "../../../constants";

export enum Provider {
  EMAIL = 'email',
  GOOGLE = 'google',
  DISCORD = 'discord',
  X = 'x',
  SMS = 'sms',
  FARCASTER = 'farcaster',
  TELEGRAM = 'telegram',
  WEBAUTHN = 'webauthn',
}

export interface AuthMethodResponseObject {
  authMethod: AuthMethod;
  authId: string; //authId
  primary_contact?: string;
  user?: AccountUserData;
  profile_picture_url?: string;
}

export enum AccountType {
  RESOLVED = 'resolved',
  CLAIMED = 'claimed',
  TRADITIONAL = 'traditional',
  EXTERNAL = 'external',
}

export interface AccountUserData {
  username?: string;
  first_name?: string;
  last_name?: string;
  middle_name?: string;
  primary_contact?: string;
  profile_picture_url?: string;
}

export interface PKPMintPayload {
  permittedIpfsCIDs: string[];
  permittedIpfsCIDScopes: number[][];
  permittedAuthMethodTypes: number[];
  permittedAuthMethodIds: string[];
  permittedAuthMethodPubkeys: string[];
  permittedAuthMethodScopes: number[][];
}

export interface PkpTransactionData {
  to: string;
  from: string;
  chainId: number;
  blockHash: string;
  blockNumber: number;
  hash: string;
  status: string;
}

export enum TransactionStatus {
  'SUCCESS' = 1,
  'FAILED' = 0,
}

export interface PkpSigningPermissions {
  litAction: boolean;
  customAuth: boolean;
  stytch: boolean;
}

export type TokenNftData = {
  image: string;
  tokenId: string;
};

export interface IExcludeAttributes {
  __v: 0;
  privateProviderUrl: 0 | 1;
  createdAt: 0;
  updatedAt: 0;
}

export class ServiceError extends Error {
  data: { message: string; error: string | null };

  constructor(message: string, error?: Error) {
    super(message);
    Object.setPrototypeOf(this, ServiceError.prototype);
    this.data = {message: this.message, error: JSON.stringify(error)};
  }
}

export enum ChainId {
  MAINNET = 1,
  GOERLI = 5,
  POLYGON_MAINNET = 137,
  POLYGON_AMOY = 80002,
  ARBITRUM = 42161,
  ARBITRUM_SEPOLIA = 421614,
  ARBITRUM_GOERLI = 421613,
  OPTIMISM = 10,
  POLYGON_ZKEVM_MAINNET = 1101,
  BASE = 8453,
  BASE_TESTNET = 84531,
  SEPOLIA = 11155111,
  BSC_MAINNET = 56,
  BSC_TESTNET = 97,
  AVAX_MAINNET = 43114,
  AVAX_TESTNET = 43113,
  LINEA_MAINNET = 59144,
  LINEA_TESTNET = 59140,
}

export const CHAIN_PROVIDERS = {
  1: ETH_MAINNET_RPC_URL,
  5: ETH_GOERLI_RPC_URL,
  137: POLYGON_MAINNET_RPC_URL,
  80002: POLYGON_AMOY_RPC_URL,
  42161: ARBITRUM_RPC_URL,
  421614: ARBITRUM_SEPOLIA_RPC_URL,
  431613: ARBITRUM_GOERLI_RPC_URL,
  10: OPTIMISM_MAINNET_RPC_URL,
  1101: POLYGON_ZKEVM_MAINNET_RPC_URL,
  8453: BASE_MAINNET_RPC_URL,
  84531: BASE_TESTNET_RPC_URL,
  11155111: ETH_SEPOLIA_RPC_URL,
  56: BSC_MAINNET_RPC_URL,
  97: BSC_TESTNET_RPC_URL,
  43114: AVALANCHE_MAINNET_RPC_URL,
  43113: AVALANCHE_FUJI_RPC_URL,
  59144: LINEA_MAINNET_RPC_URL,
  59140: LINEA_TESTNET_RPC_URL
}