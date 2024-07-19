import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ServiceError } from '../utils/types.interfaces';
import { TransactionDto } from '../dto/Transactions.dto';
import {
  PkpTransaction,
  PkpTransactionDocument,
} from '../entities/PkpTransaction.entity';
import { PkpTransactionData } from '../utils/types.interfaces';
import {
  BridgeTokens,
  BridgeTokensDocument,
} from '../entities/BridgeTokens.entity';

@Injectable()
export class PkpTransactionsRepository {
  private readonly logger = new Logger(PkpTransactionsRepository.name);
  constructor(
    @InjectModel(PkpTransaction.name)
    private pkpTransactionsModel: Model<PkpTransactionDocument>,
    @InjectModel(BridgeTokens.name)
    private bridgeTokens: Model<BridgeTokensDocument>,
  ) {}

  async addPkpTxnDb(
    transactionReq: TransactionDto,
    chainId: number,
    transaction: PkpTransactionData,
    tokenInfo: BridgeTokensDocument,
  ): Promise<PkpTransactionDocument> {
    try {
      const createdTransaction = new this.pkpTransactionsModel({
        chainId,
        ...transaction,
        tokenTransfer: tokenInfo,
        amountTransferred: transactionReq.value,
        data: transactionReq.data,
        createdAt: Date.now(),
      });
      return await createdTransaction.save();
    } catch (error) {
      throw new ServiceError('Error in adding Pkp Txn to DB', error);
    }
  }

  async fetchTransaction(address: string): Promise<PkpTransactionDocument[]> {
    try {
      const txn = await this.pkpTransactionsModel
        .find({ from: address })
        .select({ data: 0, _id: 0, __v: 0 });
      return txn;
    } catch (error) {
      throw new ServiceError(error);
    }
  }

  async fetchTokenInfo(
    chainId: number,
    tokenAddress: string,
  ): Promise<BridgeTokensDocument> {
    try {
      const response = await this.bridgeTokens.findOne({
        chainId: chainId,
        address: tokenAddress,
      });
      return response;
    } catch (error) {
      this.logger.error('Error in fetching token Info', error);
    }
  }
}
