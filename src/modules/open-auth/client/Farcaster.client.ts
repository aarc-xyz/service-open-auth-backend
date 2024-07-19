import { ethers } from 'ethers';
import { Injectable, Logger } from '@nestjs/common';
import { SiweMessage } from 'siwe';
import { FarcasterAuthDto } from '../dto/Accounts.dto';
import { ServiceError } from '../utils/types.interfaces';
import {
  FARCASTER_ID_REGISTRY_CONTRACT_ADDRESS,
  FID_URI_REGEX,
  VALID_STATEMENTS,
  VALID_CHAIN_ID,
} from '../utils/constants';
import { CHAIN_PROVIDERS } from '../utils/types.interfaces';
import { FarcasterIdRegistryAbi } from '../../../abis/FarcasterIdRegistry.abi';

@Injectable()
export class FarcasterClient {
  private readonly FARCASTER_CONTRACTS_CHAIN_ID = 10;
  private readonly logger: Logger = new Logger(FarcasterClient.name);
  private readonly provider: ethers.providers.Provider;
  private readonly farcasterIdRegistryContract: ethers.Contract;

  constructor() {
    this.provider = new ethers.providers.JsonRpcProvider(
      CHAIN_PROVIDERS[this.FARCASTER_CONTRACTS_CHAIN_ID],
    );
    // Creating a read-only contract instance
    this.farcasterIdRegistryContract = new ethers.Contract(
      FARCASTER_ID_REGISTRY_CONTRACT_ADDRESS,
      FarcasterIdRegistryAbi,
      this.provider,
    );
    this.logger.log('FarcasterClient initialized');
  }

  async verifySignature(
    data: FarcasterAuthDto,
  ): Promise<{ success: boolean; fid?: string }> {
    // verify the signature
    try {
      const fid = await this.verify(data);
      return {
        success: true,
        fid: fid,
      };
    } catch (error) {
      this.logger.error('Failed to verify farcaster data', error);
      return {
        success: false,
      };
    }
  }

  private async verify(data: FarcasterAuthDto): Promise<string> {
    try {
      const message = this.validateMessage(data.message);

      // verify the nonce and domain
      if (message.nonce !== data.nonce) {
        throw new ServiceError('Invalid nonce');
      }
      if (message.domain !== data.domain) {
        throw new ServiceError('Invalid domain');
      }

      // verify the signature
      const siwe = await message.validate(data.signature, this.provider);
      const custody = siwe.address;

      // verify the FID
      const fid = this.parseResources(message);
      const success = await this.verifyFid(fid, custody);
      if (!success) {
        throw new ServiceError('Invalid FID');
      }

      return fid;
    } catch (error) {
      throw new ServiceError('Failed to verify farcaster data', error);
    }
  }

  private validateMessage(data: string | Partial<SiweMessage>): SiweMessage {
    try {
      // Siwe message validates itself when constructed
      const message = new SiweMessage(data);

      // validate the statement and chainId
      if (!VALID_STATEMENTS.includes(message.statement)) {
        throw new ServiceError(`Statement must be '${VALID_STATEMENTS}'`);
      }

      if (message.chainId !== VALID_CHAIN_ID) {
        throw new ServiceError('Invalid chainId, Chain ID must be 10');
      }

      // validate the resources
      const resources = this.parseResources(message);
      if (!resources) {
        throw new ServiceError('No fid resource provided');
      }

      return message;
    } catch (error) {
      throw new ServiceError('Failed to validate message', error);
    }
  }

  private async verifyFid(fid: string, custody: string): Promise<boolean> {
    // get the fid
    try {
      const fetchedFid = await this.farcasterIdRegistryContract.idOf(custody);

      if (fetchedFid.toString() === fid) {
        return true;
      } else {
        return false;
      }
    } catch (error) {
      throw new ServiceError('Failed to verify FID', error);
    }
  }

  private parseResources(message: SiweMessage): string {
    const resource = (message.resources ?? []).find((resource) => {
      return FID_URI_REGEX.test(resource);
    });
    if (!resource) {
      throw new ServiceError('No fid resource provided');
    }
    const fid = resource.match(FID_URI_REGEX)?.[1] ?? '';

    if (isNaN(parseInt(fid))) {
      throw new ServiceError('Invalid fid');
    }
    return fid;
  }
}
