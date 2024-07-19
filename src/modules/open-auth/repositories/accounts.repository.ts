import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ServiceError } from '../utils/types.interfaces';
import { Accounts, AccountsDocument } from '../entities/Accounts.entity';
import {
  ExternalWallet,
  ExternalWalletDocument,
} from '../entities/ExternalWallet.entity';

@Injectable()
export class AccountsRepository {
  constructor(
    @InjectModel(Accounts.name) private accountsModel: Model<AccountsDocument>,
    @InjectModel(ExternalWallet.name)
    private externalWalletModel: Model<ExternalWalletDocument>,
  ) {}

  async findOneByKey(
    key: string,
    value: string,
  ): Promise<AccountsDocument | null> {
    const documents = await this.accountsModel.findOne({ [key]: value });
    return documents;
  }

  async createAccounts(accounts: Accounts[]): Promise<AccountsDocument[]> {
    try {
      const uniqueAccounts = await this.filterUniqueAccounts(accounts);
      if (uniqueAccounts.length === 0) {
        return [];
      }
      const createdAccounts = await this.accountsModel.insertMany(
        uniqueAccounts,
      );
      return createdAccounts;
    } catch (error) {
      throw new ServiceError('Error in creating account', error);
    }
  }

  async createExternalWallet(
    address: string,
    apiKey: string,
    walletType: string,
  ): Promise<ExternalWallet> {
    const payload = new this.externalWalletModel({
      address: address,
      createdAt: Date.now(),
      lastLoginAt: Date.now(),
      apiKeyId: apiKey,
      walletType: walletType,
    });
    return await payload.save();
  }

  async findExternalWallet(
    params: Record<string, unknown>,
  ): Promise<ExternalWalletDocument[]> {
    const query: Record<string, unknown> = {};
    for (const key in params) {
      params[key] !== '' ? (query[key] = params[key]) : null;
    }
    const exclude: Record<string, unknown> = {};
    const resultSet = await this.externalWalletModel
      .find(query, exclude)
      .sort({ createdAt: -1 })
      .exec();
    return resultSet;
  }

  async updateExternalAccount(
    account: ExternalWalletDocument,
  ): Promise<ExternalWalletDocument> {
    try {
      return await this.externalWalletModel.findByIdAndUpdate(account._id, {
        lastLoginAt: Date.now(),
        loginCount: account.loginCount + 1,
      });
    } catch (error) {
      throw new ServiceError('Update external account error', error);
    }
  }

  async updateAccount(account: AccountsDocument): Promise<void> {
    try {
      await this.accountsModel.findByIdAndUpdate(account._id, {
        claimed: true,
        updatedAt: Date.now(),
      });
    } catch (error) {
      throw new ServiceError('Update account error', error);
    }
  }

  private async filterUniqueAccounts(
    accounts: Accounts[],
  ): Promise<Accounts[]> {
    const existingAddresses = await this.findExistingKeys(accounts);
    const uniqueAccounts = accounts.filter(
      (account) => !existingAddresses.includes(account.publicKey),
    );
    return uniqueAccounts;
  }

  private async findExistingKeys(accounts: Accounts[]): Promise<string[]> {
    const publicKey = accounts.map((account) => {
      if (account) return account.publicKey;
    });
    const existingTokens = await this.accountsModel.find({
      publicKey: { $in: publicKey },
    });
    return existingTokens.map((account) => account.publicKey);
  }
}
