import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ServiceError } from '../common/types';
import { excludedAttributes } from '../common/helpers';
import { AccessControlConditions, Sessions, SessionsDocument } from "../entities/Sessions.entity";
import { AccountUserData } from '../common/types';
import { SessionSigs } from "@lit-protocol/types";

@Injectable()
export class SessionsRepository {
  private readonly logger = new Logger(SessionsRepository.name);
  constructor(
    @InjectModel(Sessions.name) private sessionsModel: Model<SessionsDocument>,
  ) {}

  async createSession(
    sessionSigs: SessionSigs,
    user: AccountUserData,
    expiresAt: Date,
    accountId: string,
    session_identifier: string,
    address: string,
    accessControlConditions: AccessControlConditions,
  ): Promise<SessionsDocument> {
    try {
      const createdSession = new this.sessionsModel({
        sessionSigs: sessionSigs,
        expiresAt: expiresAt,
        accountId: accountId,
        user: user,
        session_identifier: session_identifier,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        polled: false,
        wallet_address: address,
        accessControlConditions: accessControlConditions,
      });
      return await createdSession.save();
    } catch (error) {
      throw new ServiceError('Session creation Error', error);
    }
  }

  async updateSession(sessionSig: SessionsDocument): Promise<void> {
    await this.sessionsModel.findByIdAndUpdate(sessionSig._id, {
      sessionSigs: sessionSig.sessionSigs,
      updatedAt: Date.now(),
      polled: true,
    });
  }

  async deleteSession(sessionSig: SessionsDocument): Promise<void> {
    const dbresponse = await this.sessionsModel.deleteOne({
      _id: sessionSig._id,
    });
    this.logger.log(dbresponse);
  }

  async findOne(
    params: Record<string, unknown>,
    hideDefaults = true,
  ): Promise<SessionsDocument> {
    const query: Record<string, unknown> = {};
    for (const key in params) {
      if (params[key] !== '') {
        query[key] = params[key];
      }
    }

    const resultSet = await this.sessionsModel
      .findOne(query)
      .sort({ createdAt: -1 })
      .exec();
    return resultSet;
  }

  async find(
    params: Record<string, unknown>,
    hideDefaults = true,
  ): Promise<SessionsDocument[]> {
    const query: Record<string, unknown> = {};
    for (const key in params) {
      if (params[key] !== '') {
        query[key] = params[key];
      }
    }

    const exclude: Record<string, unknown> = {};
    if (hideDefaults) {
      Object.assign(exclude, excludedAttributes());
    }

    const resultSet = await this.sessionsModel
      .find(query, exclude)
      .sort({ createdAt: -1 })
      .exec();
    return resultSet;
  }
  async count(params: Record<string, unknown>): Promise<number> {
    const query: Record<string, unknown> = {};
    for (const key in params) {
      if (params[key] !== '') {
        query[key] = params[key];
      }
    }

    return this.sessionsModel.countDocuments(query);
  }
}
