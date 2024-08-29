import { Injectable, Logger } from '@nestjs/common';
import {
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import { v4 } from 'uuid';
import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialType,
} from '@simplewebauthn/types';
import { PassKeyRepository } from '../repositories/passKeys.repository';
import { BaseAuthProvider } from "./Base.authProvider";
import {
  AuthenticateWebAuthnDto,
  RegisterWebAuthnDto,
} from '../dto/Accounts.dto';
import { Provider, ServiceError } from "../common/types";
import { RP_NAME } from '../common/constants';

@Injectable()
export class WebAuthnProvider extends BaseAuthProvider {
  constructor(private readonly passKeyRepository: PassKeyRepository) {
    super(Provider.WEBAUTHN, WebAuthnProvider.name);
  }

  async generateCallbackUrl(): Promise<string> {
    throw new Error('Method not implemented.');
  }

  async registerCredentials(): Promise<void> {
    throw new Error('Method not implemented.');
  }

  private generateRPID(origin: string): string {
    return new URL(origin).hostname;
  }

  async generateUserRegistrationOptions(
    origin: string,
    primary_contact: string,
    wallet_address: string,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    try {
      // get already registered passkey
      const passKeys = await this.passKeyRepository.findManyByKey(
        wallet_address,
        'wallet_address',
      );

      const challenge = v4();
      const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: this.generateRPID(origin),
        userName: wallet_address,
        userDisplayName: wallet_address,
        attestationType: 'none',
        excludeCredentials: passKeys.map((passKey) => ({
          id: passKey.id,
        })),
        authenticatorSelection: {
          userVerification: 'required',
        },
        challenge: challenge,
      });

      await this.passKeyRepository.addPassKey({
        id: options.user.id,
        primary_contact: primary_contact,
        wallet_address: wallet_address,
        challenge: options.challenge,
        counter: 0,
      });

      return options;
    } catch (error) {
      this.logger.error('Error generating registration options', error.message);
      throw new ServiceError('Failed to generate registration options');
    }
  }

  async verifyRegistration(
    origin: string,
    params: RegisterWebAuthnDto,
  ): Promise<boolean> {
    try {
      const passKey = await this.passKeyRepository.findOneByKey({
        wallet_address: params.wallet_address,
      });
      const registrationCredentials: VerifyRegistrationResponseOpts = {
        response: {
          id: params.id,
          rawId: params.rawId,
          response: {
            clientDataJSON: params.clientDataJSON,
            attestationObject: params.attestationObject,
          },
          clientExtensionResults: {},
          type: 'public-key' as PublicKeyCredentialType,
        },
        expectedChallenge: passKey.challenge,
        expectedOrigin: origin,
        expectedRPID: this.generateRPID(origin),
      };
      const registrationResponse = await verifyRegistrationResponse(
        registrationCredentials,
      );
      const { verified, registrationInfo } = registrationResponse;
      if (!verified) {
        throw new ServiceError('Failed to verify registration');
      }
      if (!registrationInfo) {
        throw new ServiceError('Failed to get registration info');
      }
      this.logger.debug(registrationInfo);

      // Update using the challenge
      const updatedPassKey = await this.passKeyRepository.updatePassKey(
        passKey.challenge.toString(),
        'challenge',
        {
          credentialId: registrationInfo.credentialID,
          webAuthnPublicKey: Buffer.from(registrationInfo.credentialPublicKey),
        },
      );

      return verified;
    } catch (error) {
      this.logger.error('Error verifying registration', error.message);
    }
  }

  async verify(
    origin: string,
    params: AuthenticateWebAuthnDto,
  ): Promise<string> {
    try {
      const passKey = await this.passKeyRepository.findOneByKey({
        credentialId: params.id,
      });
      if (!passKey) {
        throw new ServiceError('PassKey not found');
      }

      const authenticationCredentials: VerifyAuthenticationResponseOpts = {
        response: {
          id: params.id,
          rawId: params.rawId,
          response: {
            clientDataJSON: params.clientDataJSON,
            authenticatorData: params.authenticatorData,
            signature: params.signature,
          },
          clientExtensionResults: {},
          type: 'public-key' as PublicKeyCredentialType,
        },
        authenticator: {
          credentialID: params.id,
          credentialPublicKey: new Uint8Array(passKey.webAuthnPublicKey),
          counter: passKey.counter,
        },
        expectedChallenge: '',
        expectedOrigin: origin,
        expectedRPID: this.generateRPID(origin),
      };

      const authenticationResponse = await verifyAuthenticationResponse(
        authenticationCredentials,
      );
      const { verified, authenticationInfo } = authenticationResponse;
      if (!verified) {
        throw new ServiceError('Failed to verify authentication');
      }
      if (!authenticationInfo) {
        throw new ServiceError('Failed to get authentication info');
      }
      this.logger.debug(authenticationInfo);

      // update the counter
      const updatedPassKey = await this.passKeyRepository.updatePassKey(
        authenticationCredentials.authenticator.credentialID,
        'credentialId',
        {
          counter: authenticationInfo.newCounter,
        },
      );
      return passKey.primary_contact;
    } catch (error) {
      this.logger.error('Error verifying webauthn authentication', error.message);
    }
  }
}
