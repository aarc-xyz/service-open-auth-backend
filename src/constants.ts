import * as dotenv from 'dotenv';

dotenv.config();

export const MONGO_DB_URL = process.env.DB_URL || '';
export const OPENAUTH_SERVICE_PORT = process.env.OPENAUTH_SERVICE_PORT || '';

// RPC_URLS
export const ETH_MAINNET_RPC_URL = process.env.ETH_MAINNET_RPC_URL || '';
export const ETH_GOERLI_RPC_URL = process.env.ETH_GOERLI_RPC_URL || '';
export const POLYGON_MAINNET_RPC_URL = process.env.POLYGON_MAINNET_RPC_URL || '';
export const POLYGON_AMOY_RPC_URL = process.env.POLYGON_AMOY_RPC_URL || '';
export const ARBITRUM_RPC_URL = process.env.ARBITRUM_RPC_URL || '';
export const ARBITRUM_SEPOLIA_RPC_URL = process.env.ARBITRUM_SEPOLIA_RPC_URL || '';
export const ARBITRUM_GOERLI_RPC_URL = process.env.ARBITRUM_GOERLI_RPC_URL || '';
export const OPTIMISM_MAINNET_RPC_URL = process.env.OPTIMISM_MAINNET_RPC_URL || '';
export const POLYGON_ZKEVM_MAINNET_RPC_URL = process.env.POLYGON_ZKEVM_MAINNET_RPC_URL || '';
export const BASE_MAINNET_RPC_URL = process.env.BASE_MAINNET_RPC_URL || '';
export const BASE_TESTNET_RPC_URL = process.env.BASE_TESTNET_RPC_URL || '';
export const ETH_SEPOLIA_RPC_URL = process.env.ETH_SEPOLIA_RPC_URL || '';
export const BSC_MAINNET_RPC_URL = process.env.BSC_MAINNET_RPC_URL || '';
export const BSC_TESTNET_RPC_URL = process.env.BSC_TESTNET_RPC_URL || '';
export const AVALANCHE_MAINNET_RPC_URL = process.env.AVALANCHE_MAINNET_RPC_URL || '';
export const AVALANCHE_FUJI_RPC_URL = process.env.AVALANCHE_FUJI_RPC_URL || '';
export const LINEA_MAINNET_RPC_URL = process.env.LINEA_MAINNET_RPC_URL || '';
export const LINEA_TESTNET_RPC_URL = process.env.LINEA_TESTNET_RPC_URL || '';

export const validateEnvironmentVariables = (): void => {
  const missingVariables = [];

  if (!MONGO_DB_URL) missingVariables.push('DB_URL');
  if (!OPENAUTH_SERVICE_PORT) missingVariables.push('OPENAUTH_SERVICE_PORT');

  // RPC_URLS
  if (!ETH_MAINNET_RPC_URL) missingVariables.push('ETH_MAINNET_RPC_URL');
  if (!ETH_GOERLI_RPC_URL) missingVariables.push('ETH_GOERLI_RPC_URL');
  if (!POLYGON_MAINNET_RPC_URL) missingVariables.push('POLYGON_MAINNET_RPC_URL');
  if (!POLYGON_AMOY_RPC_URL) missingVariables.push('POLYGON_AMOY_RPC_URL');
  if (!ARBITRUM_RPC_URL) missingVariables.push('ARBITRUM_RPC_URL');
  if (!ARBITRUM_SEPOLIA_RPC_URL) missingVariables.push('ARBITRUM_SEPOLIA_RPC_URL');
  if (!ARBITRUM_GOERLI_RPC_URL) missingVariables.push('ARBITRUM_GOERLI_RPC_URL');
  if (!OPTIMISM_MAINNET_RPC_URL) missingVariables.push('OPTIMISM_MAINNET_RPC_URL');
  if (!POLYGON_ZKEVM_MAINNET_RPC_URL) missingVariables.push('POLYGON_ZKEVM_MAINNET_RPC_URL');
  if (!BASE_MAINNET_RPC_URL) missingVariables.push('BASE_MAINNET_RPC_URL');
  if (!BASE_TESTNET_RPC_URL) missingVariables.push('BASE_TESTNET_RPC_URL');
  if (!ETH_SEPOLIA_RPC_URL) missingVariables.push('ETH_SEPOLIA_RPC_URL');
  if (!BSC_MAINNET_RPC_URL) missingVariables.push('BSC_MAINNET_RPC_URL');
  if (!BSC_TESTNET_RPC_URL) missingVariables.push('BSC_TESTNET_RPC_URL');
  if (!AVALANCHE_MAINNET_RPC_URL) missingVariables.push('AVALANCHE_MAINNET_RPC_URL');
  if (!AVALANCHE_FUJI_RPC_URL) missingVariables.push('AVALANCHE_FUJI_RPC_URL');
  if (!LINEA_MAINNET_RPC_URL) missingVariables.push('LINEA_MAINNET_RPC_URL');
  if (!LINEA_TESTNET_RPC_URL) missingVariables.push('LINEA_TESTNET_RPC_URL');

  if (missingVariables.length > 0) {
    throw new Error(
        `Missing environment variables: ${missingVariables.join(', ')}`,
    );
  }
};
