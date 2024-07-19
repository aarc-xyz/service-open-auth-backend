import { BadRequestException, HttpStatus, Logger } from '@nestjs/common';
import { ethers } from 'ethers';
import { SessionsDocument } from '../entities/Sessions.entity';
import {
  AARC_CUSTOM_AUTH_SALT,
  LIT_CLAIM_KEY_ACTION_CID,
  LIT_CUSTOM_AUTH_TYPE_ID,
} from './constants';
import { MESSAGES } from './response.messages';
import * as crypto from 'node:crypto';
import * as bs58 from 'bs58';
import { SessionSigs } from '@lit-protocol/types';
import { IExcludeAttributes } from "./types.interfaces";

/**
 *
 * @returns
 * @description this function includes attributes that needs to be hide from database response
 */
export const excludedAttributes = (): IExcludeAttributes => {
  return {
    __v: 0,
    createdAt: 0,
    updatedAt: 0,
    privateProviderUrl: 0,
  };
};

/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable @typescript-eslint/explicit-module-boundary-types*/
export const sendServiceDownError = (err) => {
  if (err.response) throw err;
  else {
    throw new BadRequestException({
      code: HttpStatus.BAD_REQUEST,
      message: err.message ? err.message : MESSAGES.SERVICE_TEMPORARY_DOWN,
    });
  }
};

export function reconstructSessionSigs(
  clientAuthkey: string,
  sessionSigs: SessionSigs,
): SessionSigs {
  Object.values(sessionSigs)[0].sig =
    clientAuthkey + Object.values(sessionSigs)[0].sig;
  return sessionSigs;
}

export async function deconstructSessionSigs(
  sessionDoc: SessionsDocument,
): Promise<{ clientSessionKey: string; serverSessionSig: SessionsDocument }> {
  if (new Date(sessionDoc.expiresAt).valueOf() < Date.now()) {
    throw new Error('The session has expired');
  }
  const signature = Object.values(sessionDoc.sessionSigs)[0].sig;
  const nodeIp = Object.keys(sessionDoc.sessionSigs)[0];
  const clientSessionKey = signature.slice(0, Math.floor(signature.length / 2));
  const serverSessionKey = signature.slice(Math.floor(signature.length / 2));
  sessionDoc.sessionSigs[nodeIp].sig = serverSessionKey;
  return { clientSessionKey: clientSessionKey, serverSessionSig: sessionDoc };
}
/**
 *
 * @param apiKey
 * @dessciption this function will convert normal key to key hash
 * @returns
 */
export function keyToKeyHash(apiKey: string) {
  const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  return keyHash;
}

export function generateLitKeyId(userId: string) {
  return ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(`${LIT_CLAIM_KEY_ACTION_CID}_${userId}`),
  );
}

export function errorData(message: string, error: Error = null) {
  return JSON.stringify({ message, error });
}

export function customAuthMethod(contact: string): {
  id: string;
  authMethodType: number;
} {
  const id = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(`${contact}: ${AARC_CUSTOM_AUTH_SALT}`),
  );
  return { id: id, authMethodType: LIT_CUSTOM_AUTH_TYPE_ID };
}

export function customAuthAction(cid: string): string {
  const base58Cid = bs58.decode(cid);
  return `0x${Buffer.from(base58Cid).toString('hex')}`;
}

export function generateHamcSignature(signingKey: string, data: string) {
  return crypto.createHmac('sha1', signingKey).update(data).digest('base64');
}
