import { ethers } from 'ethers';
import { LitContracts } from '@lit-protocol/contracts-sdk';
import {CHRONICLE_RPC_URL, LIT_CLIENT_NETWORK, LIT_CONTROLLER_PRIVATE_KEY} from "../utils/constants";

const PRIVATE_KEY = LIT_CONTROLLER_PRIVATE_KEY;

const PROVIDER = CHRONICLE_RPC_URL;

const main = async (): Promise<string> => {
  const provider = new ethers.providers.JsonRpcProvider(PROVIDER);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  const litContractClient = new LitContracts({
    signer: wallet,
    network: LIT_CLIENT_NETWORK,
  });

  await litContractClient.connect();

  // mint capacity credits
  const response = await litContractClient.mintCapacityCreditsNFT({
    requestsPerKilosecond: 1000,
    daysUntilUTCMidnightExpiration: 30,
  });

  console.log(response.capacityTokenIdStr);
  return response.capacityTokenIdStr;
};

main().catch((err) => console.error(err));
