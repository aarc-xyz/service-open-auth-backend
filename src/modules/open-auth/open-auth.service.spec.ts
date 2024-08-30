import { Test, TestingModule } from '@nestjs/testing';
import { LitClient } from './clients/Lit.client';
import { OpenAuthService } from './open-auth.service';
import { AccountsRepository } from './repositories/accounts.repository';
import {
  AuthMethodResponseObject,
  Provider, TokenNftData
} from "./common/types";
import {
  ClaimAccountDto,
  FarcasterAuthDto,
  GetPubKeyDto,
  TelegramAuthDto,
} from './dto/Accounts.dto';
import { StytchClient } from './clients/Stytch.client';
import { FarcasterAuthProvider } from "./authProviders/Farcaster.authProvider";
import { TelegramAuthProvider } from "./authProviders/Telegram.authProvider";
import { TwitterAuthProvider } from "./authProviders/Twitter.authProvider";
import { WebAuthnProvider } from "./authProviders/Webauthn.authProvider";
import { SessionsRepository } from './repositories/sessions.repository';
import { TransactionsOperationDto } from './dto/Transactions.dto';
import { ethers } from 'ethers';
import { PollSession } from './dto/Sessions.dto';
import { PkpTransactionsRepository } from './repositories/pkptransactions.repository';
import { NonceUsedRepository } from './repositories/nonce.repository';
import { NativeAuthClient } from './clients/NativeAuth.client';
import { AuthMethodType } from '@lit-protocol/constants';
import { OAuthClientDataRepository } from './repositories/OAuthClientData.repository';
import { AuthProvidersDto } from './dto/AuthProviders.dto';
import { PassKeyRepository } from './repositories/PassKeys.repository';
import { TokenAndSecretRepository } from './repositories/TokenAndSecret.repository';
import * as jwt from 'jsonwebtoken';
import { Request } from "express";
import { PlatformAuthClient } from "./clients/PlatformAuth.client";
import { TwilioAuthProvider } from "./authProviders/Twilio.authProvider";
import { LIT_CUSTOM_AUTH_TYPE_ID } from "./common/constants";

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(),
}));

describe('OpenAuthService', () => {
  let service: OpenAuthService;

  const mockAccountsRepository = {
	createAccounts: jest.fn(),
	findOneByKey: jest.fn(),
  };

  const mockOAuthClientDataRepository = {
	findOneByKey: jest.fn(),
	addOrUpdateClientData: jest.fn(),
  };

  const mockPlatformAuthClient = {
	verifyRequest: jest.fn(),
  }

  const mockNativeAuthClient = {
	hasNativeAuthEnabled: jest.fn(),
	registerCredentials: jest.fn(),
	getCallbackUrl: jest.fn(),
	verifyRequest: jest.fn(),
  };

  const mockTokenAndSecretRepository = {
	findOneByKey: jest.fn(),
	addTokenAndSecret: jest.fn(),
  };

  const mockApiKeysRepository = {
	findOne: jest.fn(),
  };

  const mockSessionsRepository = {
	createSession: jest.fn(),
	findOne: jest.fn(),
	find: jest.fn(),
	updateSession: jest.fn(),
	deleteSession: jest.fn(),
  };

  const mockStytchClient = {
	handleProviderOauth: jest.fn(),
	sendEmail: jest.fn(),
	verifyEmailOTP: jest.fn(),
	validateEmailOTP: jest.fn(),
  };

  const mockFarcasterAuthProvider = {
	verifySignature: jest.fn(),
	verify: jest.fn(),
	validateMessage: jest.fn(),
	verifyFid: jest.fn(),
  };

  const mockTwitterAuthProvider = {
	generateRequestToken: jest.fn(),
	generateAccessToken: jest.fn(),
	getTwitterAccountCredentials: jest.fn(),
	generateXAuthHeader: jest.fn(),
  };

  const mockTelegramAuthProvider = {
	verify: jest.fn(),
  };

  const mockLitClient = {
	init: jest.fn(),
	close: jest.fn(),
	computeCFAFromUserID: jest.fn(),
	generateProviderAuthMethod: jest.fn(),
	claimKeyId: jest.fn(),
	getCustomAuthSessionSigs: jest.fn(),
	getControllerAuthSig: jest.fn(),
	getPubKeysFromAuthMethod: jest.fn(),
	getSessionSigs: jest.fn(),
	getPKPEtherWallet: jest.fn(),
	callLitAction: jest.fn(),
  };

  const mockWebAuthnProvider = {
	verifyRegistration: jest.fn(),
	verifyAuthentication: jest.fn(),
	connectWebAuthn: jest.fn(),
	generateUserRegistrationOptions: jest.fn(),
  };

  const mockTwilioAuthProvider = {
	verifyPasscode: jest.fn(),
	sendPasscode: jest.fn(),
  }

  const mockPassKeyRepository = {
	findOneByKey: jest.fn(),
	addPassKey: jest.fn(),
  };

  beforeEach(async () => {
	const module: TestingModule = await Test.createTestingModule({
	  providers: [
		OpenAuthService,
		LitClient,
		{ provide: LitClient, useValue: mockLitClient },
		StytchClient,
		{ provide: StytchClient, useValue: mockStytchClient },
		FarcasterAuthProvider,
		{ provide: FarcasterAuthProvider, useValue: mockFarcasterAuthProvider },
		PlatformAuthClient,
		{ provide: PlatformAuthClient, useValue: mockPlatformAuthClient },
		NativeAuthClient,
		{ provide: NativeAuthClient, useValue: mockNativeAuthClient },
		WebAuthnProvider,
		{ provide: WebAuthnProvider, useValue: mockWebAuthnProvider },
		TwitterAuthProvider,
		{ provide: TwitterAuthProvider, useValue: mockTwitterAuthProvider },
		TelegramAuthProvider,
		{ provide: TelegramAuthProvider, useValue: mockTelegramAuthProvider },
		TwilioAuthProvider,
		{ provide: TwilioAuthProvider, useValue: mockTwilioAuthProvider },
		AccountsRepository,
		{ provide: AccountsRepository, useValue: mockAccountsRepository },
		SessionsRepository,
		{ provide: SessionsRepository, useValue: mockSessionsRepository },
		PkpTransactionsRepository,
		{
		  provide: PkpTransactionsRepository,
		  useValue: PkpTransactionsRepository,
		},
		NonceUsedRepository,
		{
		  provide: NonceUsedRepository,
		  useValue: NonceUsedRepository,
		},
		OAuthClientDataRepository,
		{
		  provide: OAuthClientDataRepository,
		  useValue: mockOAuthClientDataRepository,
		},
		PassKeyRepository,
		{ provide: PassKeyRepository, useValue: mockPassKeyRepository },
		TokenAndSecretRepository,
		{
		  provide: TokenAndSecretRepository,
		  useValue: mockTokenAndSecretRepository,
		},
	  ],
	}).compile();

	service = module.get<OpenAuthService>(OpenAuthService);
  });

  afterAll((done) => {
	done();
  });

  it('should be defined', () => {
	expect(service).toBeDefined();
  });

  describe('claim-account', () => {
	const fetchedAccount = {
	  _id: '65faf2ad47c963c666a4b0a9',
	  key: 'x-test',
	  pkpAddress: '0x834D1200D67AC61d5728602AeD89A2bA75327B87',
	  publicKey:
		'0x04e68e78901d5a48ef59c1d048370b542d9b61b3c91e998b8f00b66ab6a77802bd1e4871e822a6dba9578c2e2c1cc5024fdd32a4e4f05cda86aeaa4659d34d6344',
	  keyId:
		'0x42bd86da8b09149ee8e9b1304cad6724271acdc56b24bc5532d54b6f9c64d2d5',
	  userId: 'ec636513-dcab-40ea-b841-725cec533371',
	  authProvider: 'x',
	  authId: 'test',
	  tokenId: 'test',
	  claimed: false,
	  createdAt: 1710834916230,
	  updatedAt: 1710834916230,
	  __v: { $numberInt: '0' },
	};
	const mockClaimParams: ClaimAccountDto = {
	  provider: Provider.X,
	  authKey: 'twitter_test_auth_key',
	  session_identifier: 'testsession_identifier',
	  expiration: 1716348670000,
	};
	it('should throw error for no account', async () => {
	  mockAccountsRepository.findOneByKey.mockResolvedValue(null);
	  await expect(service.claimAccount(mockClaimParams)).rejects.toThrowError(
		Error,
	  );
	});

	it('should throw error if Account already claimed', async () => {
	  const mockClaimedAccount = { ...fetchedAccount, claimed: true };
	  mockAccountsRepository.findOneByKey.mockResolvedValue(mockClaimedAccount);
	  await expect(service.claimAccount(mockClaimParams)).rejects.toThrowError(
		Error,
	  );
	});
  });

  describe('authenticate', () => {
	const mockApiResponse = {
	  _id: { $oid: '66058faf77016870a7026170' },
	  createdAt: { $numberDouble: '1711640495995.0' },
	  updatedAt: { $numberDouble: '1711640495995.0' },
	  apiKey:
		'bbf657c9a9976d1b0bd6ea823cf33be4b9a961ba126bf6742331ac85b5cf53dc',
	  projectName: 'test_oauth',
	  userId: { $oid: '660519aeffff7ab36de4dec5' },
	  __v: { $numberInt: '0' },
	};

	const fetchedAccount = {
	  _id: '65faf2ad47c963c666a4b0a9',
	  key: 'x-test',
	  pkpAddress: '0x834D1200D67AC61d5728602AeD89A2bA75327B87',
	  publicKey:
		'0x04e68e78901d5a48ef59c1d048370b542d9b61b3c91e998b8f00b66ab6a77802bd1e4871e822a6dba9578c2e2c1cc5024fdd32a4e4f05cda86aeaa4659d34d6344',
	  keyId:
		'0x42bd86da8b09149ee8e9b1304cad6724271acdc56b24bc5532d54b6f9c64d2d5',
	  userId: 'ec636513-dcab-40ea-b841-725cec533371',
	  authProvider: 'google',
	  authId: 'test',
	  tokenId: 'test',
	  claimed: false,
	  accountType: 'claimed',
	  createdAt: 1710834916230,
	  updatedAt: 1710834916230,
	  __v: { $numberInt: '0' },
	};

	const mockInputParams = {
	  provider: Provider.GOOGLE,
	  identifier: 'test22',
	  authKey: 'test_X_auth_token',
	  chainId: 80001,
	  session_identifier: 'unique_client_session_identifier',
	};

	const mockPkpPublicKeys = {
	  publicKey:
		'0x0432269de9b27eb6b2ceb62a421f25f71f8112951857abc17593981e8567a6d6aa5d89678be598c862b7e63e9d50f52d7c80a6d7b42bd51c26ae56873de188aa35',
	  tokenId: '0xsample',
	  signingPermissions: {
		litAction: true,
		customAuth: true,
		stytch: true,
	  },
	};

	const mockProviderAuthValue = {
	  request_id: 'request-id-test-8126d986-8462-4922-bb5b-320c6d51d6b5',
	  session: {
		attributes: {
		  ip_address: '',
		  user_agent: '',
		},
		authentication_factors: [
		  {
			created_at: '2024-04-24T12:41:30Z',
			delivery_method: 'oauth_google',
			google_oauth_factor: {
			  email_id: '',
			  id: 'oauth-user-test-99b07cf8-fe07-43a1-8334-5b005c8f3c5a',
			  provider_subject: '104885251007036135002',
			},
			last_authenticated_at: '2024-04-24T12:41:30Z',
			type: 'oauth',
			updated_at: '2024-04-24T12:41:30Z',
		  },
		],
		custom_claims: {},
		expires_at: '2024-05-01T12:41:30Z',
		last_accessed_at: '2024-04-24T12:41:31Z',
		session_id: 'session-test-eea43472-fcb5-40fa-9374-7c2c8ebd6e83',
		started_at: '2024-04-24T12:41:30Z',
		user_id: 'user-test-0a9c3131-6aa5-4a90-807a-669e05d41b33',
	  },
	  session_jwt:
		'eyJhbGciOiJSUzI1NiIsImtpZCI6Imp3ay10ZXN0LWQxNmE5ZGE1LWQzMTktNDA4NS05N2Y3LWQ2N2QxN2E1MmQ4OSIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicHJvamVjdC10ZXN0LWNjNDk4ZjgzLWM2YmUtNGI1YS05ODg1LWEyZTc5OWYyMTY2YiJdLCJleHAiOjE3MTM5NjI3OTEsImh0dHBzOi8vc3R5dGNoLmNvbS9zZXNzaW9uIjp7ImlkIjoic2Vzc2lvbi10ZXN0LWVlYTQzNDcyLWZjYjUtNDBmYS05Mzc0LTdjMmM4ZWJkNmU4MyIsInN0YXJ0ZWRfYXQiOiIyMDI0LTA0LTI0VDEyOjQxOjMwWiIsImxhc3RfYWNjZXNzZWRfYXQiOiIyMDI0LTA0LTI0VDEyOjQxOjMxWiIsImV4cGlyZXNfYXQiOiIyMDI0LTA1LTAxVDEyOjQxOjMwWiIsImF0dHJpYnV0ZXMiOnsidXNlcl9hZ2VudCI6IiIsImlwX2FkZHJlc3MiOiIifSwiYXV0aGVudGljYXRpb25fZmFjdG9ycyI6W3sidHlwZSI6Im9hdXRoIiwiZGVsaXZlcnlfbWV0aG9kIjoib2F1dGhfZ29vZ2xlIiwibGFzdF9hdXRoZW50aWNhdGVkX2F0IjoiMjAyNC0wNC0yNFQxMjo0MTozMFoiLCJnb29nbGVfb2F1dGhfZmFjdG9yIjp7ImlkIjoib2F1dGgtdXNlci10ZXN0LTk5YjA3Y2Y4LWZlMDctNDNhMS04MzM0LTViMDA1YzhmM2M1YSIsInByb3ZpZGVyX3N1YmplY3QiOiIxMDQ4ODUyNTEwMDcwMzYxMzUwMDIifX1dfSwiaWF0IjoxNzEzOTYyNDkxLCJpc3MiOiJzdHl0Y2guY29tL3Byb2plY3QtdGVzdC1jYzQ5OGY4My1jNmJlLTRiNWEtOTg4NS1hMmU3OTlmMjE2NmIiLCJuYmYiOjE3MTM5NjI0OTEsInN1YiI6InVzZXItdGVzdC0wYTljMzEzMS02YWE1LTRhOTAtODA3YS02NjllMDVkNDFiMzMifQ.NnsGCV6rfeNoaFeKl9fWf2Eeb3GOMK-i27nTHBl0i_l3dbfogvZJuPTPAlZDYquCNOGGayDgDyMR-dRMj4romA9kgwFhbnyEM96YKX6ICkYB0vgYZDH9l0MntbzlSqMxvhjLhMfI6lQzE0kKvlM4CBZrWHlE5qBDJPv35D-DpPU8oQuHFqXAStFh0Nim0VLQjohba3HHYW_7VB04Byuh_vUiIkKog3p9BmCND3DGuROLM4mOH877h4psh-AiaGBaC0s81ox_WLFITjwyJWmO__U5D6h4LlMSZynNycGZHJsMnWLmva0u8SIKKP6sd_xdnMzvj__eN3SlW_-9dbVr-Q',
	  session_token: '3uJupS7KGCx_ZFuhZD-innzoA_O4_KPHos61F__B3Ig5',
	  status_code: 200,
	  user: {
		biometric_registrations: [],
		created_at: '2024-03-27T05:14:42Z',
		crypto_wallets: [],
		emails: [
		  {
			email: 'johndoe@example.com',
			email_id: 'email-test-e69acc9b-3b7a-495b-8233-3d5ca814afcb',
			verified: true,
		  },
		],
		name: {
		  first_name: 'John',
		  last_name: 'Doe',
		  middle_name: '',
		},
		password: null,
		phone_numbers: [],
		providers: [
		  {
			locale: 'en-US',
			oauth_user_registration_id:
			  'oauth-user-test-96825a06-8d95-4a2c-9801-6faf48ff5fd7',
			profile_picture_url: '',
			provider_subject: '1222443343137607742',
			provider_type: 'Discord',
		  },
		  {
			locale: '',
			oauth_user_registration_id:
			  'oauth-user-test-99b07cf8-fe07-43a1-8334-5b005c8f3c5a',
			profile_picture_url:
			  'https://lh3.googleusercontent.com/a/ACg8ocLnhS2Dd8vSb8bKfMGoa-EmoSTuahRoFmy4dFgR74Wvtw6HVw=s96-c',
			provider_subject: '104885251007036135002',
			provider_type: 'Google',
		  },
		],
		status: 'active',
		totps: [],
		trusted_metadata: {},
		untrusted_metadata: {},
		user_id: 'user-test-0a9c3131-6aa5-4a90-807a-669e05d41b33',
		webauthn_registrations: [],
	  },
	};

	const mockPublicKeys = [
	  {
		publicKey:
		  '0x0432269de9b27eb6b2ceb62a421f25f71f8112951857abc17593981e8567a6d6aa5d89678be598c862b7e63e9d50f52d7c80a6d7b42bd51c26ae56873de188aa35',
		tokenId: 'test1',
		signingPermissions: {
		  litAction: true,
		  customAuth: true,
		  stytch: true,
		},
	  },
	  {
		publicKey:
		  '0x04d85f6060515505f1487a1f6c1581a897cd0a40f93e3b00d95618b3624541c52dafa97d6a3af4c89d8785afb38a638c2b1095f988fd8c1e320c16591ca6145fe3',
		tokenId:
		  '46170275471322998493492027186703442902685729932638325354933403158989776392840',
		signingPermissions: {
		  litAction: true,
		  customAuth: true,
		  stytch: true,
		},
	  },
	];

	const mockTelegramAuthDto: TelegramAuthDto = {
	  id: '123',
	  auth_date: Date.now() / 1000,
	  first_name: 'test',
	  last_name: 'test',
	  username: 'test',
	  photo_url: 'example.com/test',
	  hash: 'test_hash',
	};

	const req: Request = {
	  headers: {
		origin: 'https://example.com',
	  },
	  body: {
		accessControlConditions: {
		  origin: 'test',
		  agent: 'test',
		},
	  },
	} as unknown as Request;

	it('should return a pkpaddress for existing publicKey', async () => {
	  mockLitClient.generateProviderAuthMethod.mockResolvedValue({
		authMethod: { authMethodType: 9, accessToken: 'sample_access_token' },
		authId: 'mock_authId',
	  });
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)
	  mockStytchClient.handleProviderOauth.mockResolvedValue(
		mockProviderAuthValue,
	  );
	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );
	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });
	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });
	  const result = await service.authenticate(
		mockInputParams,
		'test22sample',
		req,
	  );
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should return a pkpaddress string for existing pkp, with no existingAccount', async () => {
	  mockLitClient.generateProviderAuthMethod.mockResolvedValue({
		authMethod: { authMethodType: 9, accessToken: 'sample_access_token' },
		id: 'mock_authId',
	  });
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)
	  mockStytchClient.handleProviderOauth.mockResolvedValue(
		mockProviderAuthValue,
	  );
	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );
	  mockAccountsRepository.findOneByKey.mockResolvedValue(null);
	  mockAccountsRepository.createAccounts.mockResolvedValue([fetchedAccount]);
	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });
	  const result = await service.authenticate(
		mockInputParams,
		'test22sample',
		req,
	  );
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should throw error if email otp not passed in email auth', async () => {
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  await expect(
		service.authenticate(
		  { ...mockInputParams, provider: Provider.EMAIL },
		  'test22sample',
		  req,
		),
	  ).rejects.toThrowError();
	});

	it('should return a pkpaddress string for EMAIL provider', async () => {
	  mockLitClient.generateProviderAuthMethod.mockResolvedValue({
		authMethod: { authMethodType: 9, accessToken: 'sample_access_token' },
		authId: 'mock_authId',
	  });
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)
	  mockStytchClient.validateEmailOTP.mockResolvedValue({
		session_jwt: 'sample_stytch_session_jwt',
	  });

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );
	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });
	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });
	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.EMAIL,
		  method_id: 'sample_method_id',
		  code: '000000',
		},
		'test22sample_apihash',
		req,
	  );
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should return a pkpaddress string for X provider', async () => {
	  mockTwitterAuthProvider.generateAccessToken.mockResolvedValue({
		oauth_token: 'test_oauth_token',
		user_id: 'test_user_id',
		screen_name: 'test_screen_name',
	  });

	  mockTwitterAuthProvider.generateXAuthHeader.mockReturnValue(
		'test_x_auth_header',
	  );

	  mockTwitterAuthProvider.getTwitterAccountCredentials.mockResolvedValue({
		email: 'test@example.com',
		profile_picture_url: 'example.com/test_profile_picture_url',
		name: 'test_name',
	  });

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );
	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });
	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });
	  mockLitClient.callLitAction.mockResolvedValue({
		signatures: {
		  sig1: {
			signature: '0xtestsignature',
		  },
		},
		response: { message: 'signed_message' },
	  });
	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.X,
		  x_session: {
			oauth_token: 'test_x_auth_token',
			oauth_verifier: 'test_x_auth_verifier',
		  },
		},
		'test22sample_apihash',
		req,
	  );
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should throw error if x_session is not passed in X auth', async () => {
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  await expect(
		service.authenticate(
		  { ...mockInputParams, provider: Provider.X },
		  'test22sample',
		  req,
		),
	  ).rejects.toThrowError();
	});

	it('should return a pkpaddress string for SMS provider', async () => {
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)

	  jest.spyOn(global, 'fetch').mockImplementation(
		jest.fn(() =>
		  Promise.resolve({
			json: () => Promise.resolve({ status: 'approved' }),
		  }),
		) as jest.Mock,
	  );

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );
	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });
	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });
	  mockLitClient.callLitAction.mockResolvedValue({
		signatures: {
		  sig1: {
			signature: '0xtestsignature',
		  },
		},
		response: { message: 'signed_message' },
	  });
	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.SMS,
		  code: '123456',
		  phone_number: '+918975638974',
		},
		'test22sample_apihash',
		req,
	  );
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should throw error if otp or phone number not passed in sms auth', async () => {
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  await expect(
		service.authenticate(
		  { ...mockInputParams, provider: Provider.SMS },
		  'test22sample',
		  req,
		),
	  ).rejects.toThrowError();
	});

	it('should return a pkpaddress string for 0 existing pkp', async () => {
	  mockLitClient.generateProviderAuthMethod.mockResolvedValue({
		authMethod: { authMethodType: 9, accessToken: 'sample_access_token' },
		authId: 'mock_authId',
	  });
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)
	  mockStytchClient.validateEmailOTP.mockResolvedValue({
		session_jwt: 'sample_stytch_session_jwt',
	  });

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(null);
	  mockLitClient.claimKeyId.mockResolvedValue({
		pkpAddress: 'claimed_pkp_address',
		pkpPublicKey:
		  '0432269de9b27eb6b2ceb62a421f25f71f8112951857abc17593981e8567a6d6aa5d89678be598c862b7e63e9d50f52d7c80a6d7b42bd51c26ae56873de188aa35',
		tokenId: 'claimed_token_id',
		signingPermissions: {
		  litAction: true,
		  customAuth: true,
		  stytch: true,
		},
	  });
	  mockAccountsRepository.findOneByKey.mockResolvedValue(null);
	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });
	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.EMAIL,
		  method_id: 'sample_method_id',
		  code: '000000',
		},
		'test22sample_apihash',
		req,
	  );
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('Should throw error when farcaster session data is not provided', async () => {
	  const mockVerifySignatureResponse = {
		success: true,
		fid: '123',
	  };

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  await expect(
		service.authenticate(
		  {
			...mockInputParams,
			provider: Provider.FARCASTER,
		  },
		  'test22sample_apihash',
		  req,
		),
	  ).rejects.toThrowError();
	});

	it('Should return a pkpaddress string for FARCASTER provider', async () => {
	  const mockFarcasterAuthDto: FarcasterAuthDto = {
		message: 'test_message',
		nonce: 'test_nonce',
		domain: 'test_domain',
		signature: 'test_signature',
	  };

	  const mockVerifySignatureResponse = {
		success: true,
		fid: '123',
	  };

	  const mockExecuteJsResponse = {
		signatures: {},
		decryptions: [],
		response: 'Mock response',
		logs: 'Mock logs',
		claims: {
		  claim1: {
			signatures: [
			  {
				r: '0x1234567890abcdef',
				s: '0xabcdef1234567890',
				recoveryParam: 0,
			  },
			],
			derivedKeyId: 'mockDerivedKeyId1',
		  },
		  claim2: {
			signatures: [
			  {
				r: '0xabcdef1234567890',
				s: '0x1234567890abcdef',
				recoveryParam: 1,
			  },
			],
			derivedKeyId: 'mockDerivedKeyId2',
		  },
		},
		debug: {
		  allNodeResponses: [
			{
			  node: 'mockNode1',
			  response: 'mockNodeResponse1',
			},
			{
			  node: 'mockNode2',
			  response: 'mockNodeResponse2',
			},
		  ],
		  allNodeLogs: [
			{
			  node: 'mockNode1',
			  logs: 'mockNodeLogs1',
			},
			{
			  node: 'mockNode2',
			  logs: 'mockNodeLogs2',
			},
		  ],
		  rawNodeHTTPResponses: {},
		},
	  };

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)
	  mockFarcasterAuthProvider.verifySignature.mockResolvedValue(
		mockVerifySignatureResponse,
	  );

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );

	  mockAccountsRepository.findOneByKey.mockResolvedValue(null);

	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });

	  mockLitClient.callLitAction.mockResolvedValue(mockExecuteJsResponse);

	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.FARCASTER,
		  farcaster_session: mockFarcasterAuthDto,
		},
		'test22sample_apihash',
		req,
	  );
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should return the wallet with most balance', async () => {
	  const mockCovalentData = [
		{
		  address: '0x1cD4147AF045AdCADe6eAC4883b9310FD286d95a',
		  updated_at: '1700000000',
		  next_update_at: '1700000000',
		  quote_currency: 'USD',
		  chain_id: 80001,
		  chain_name: 'Polygon',
		  items: [
			{
			  contract_decimals: 18,
			  contract_name: 'Wrapped Ether',
			  contract_ticker_symbol: 'WETH',
			  contract_address: '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619',
			  supports_erc: ['erc20'],
			  logo_url:
				'https://logos.covalenthq.com/tokens/0x7ceb23fd6bc0add59e62ac25578270cff1b9f619.png',
			  contract_display_name: 'Wrapped Ether',
			  logo_urls: {
				token_logo_url:
				  'https://logos.covalenthq.com/tokens/0x7ceb23fd6bc0add59e62ac25578270cff1b9f619.png',
				protocol_logo_url: null,
				chain_logo_url: 'https://logos.covalenthq.com/chains/1.png',
			  },
			  list_transferred_at: '1700000000',
			  native_token: false,
			  type: 'cryptocurrency',
			  is_spam: false,
			  balance: '0.1',
			  balance_24h: '0.1',
			  quote_rate: '2003.2',
			  quote_rate_24h: '2003.2',
			  quote: '200.32',
			  pretty_quote: '$200.32',
			  quote_24h: '200.32',
			  pretty_quote_24h: '$200.32',
			  nft_data: [] as TokenNftData[],
			},
			{
			  contract_decimals: 6,
			  contract_name: 'Tether USD',
			  contract_ticker_symbol: 'USDT',
			  contract_address: '0x2791bca1f2de4661ed88a30c99a7a9449aa84174',
			  supports_erc: ['erc20'],
			  logo_url:
				'https://logos.covalenthq.com/tokens/0x2791bca1f2de4661ed88a30c99a7a9449aa84174.png',
			  contract_display_name: 'Tether USD',
			  logo_urls: {
				token_logo_url:
				  'https://logos.covalenthq.com/tokens/0x2791bca1f2de4661ed88a30c99a7a9449aa84174.png',
				protocol_logo_url: null,
				chain_logo_url: 'https://logos.covalenthq.com/chains/1.png',
			  },
			  list_transferred_at: '1700000000',
			  native_token: false,
			  type: 'stablecoin',
			  is_spam: false,
			  balance: '200',
			  balance_24h: '200',
			  quote_rate: '1.0',
			  quote_rate_24h: '1.0',
			  quote: '200.0',
			  pretty_quote: '$200.0',
			  quote_24h: '200.0',
			  pretty_quote_24h: '$200.0',
			  nft_data: [] as TokenNftData[],
			},
		  ],
		},
		{
		  address: '0x1cD4147AF045AdCADe6eAC4883b9310FD286d95a',
		  updated_at: '1700000000',
		  next_update_at: '1700000000',
		  quote_currency: 'USD',
		  chain_id: 80001,
		  chain_name: 'Polygon',
		  items: [
			{
			  contract_decimals: 18,
			  contract_name: 'Wrapped Ether',
			  contract_ticker_symbol: 'WETH',
			  contract_address: '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619',
			  supports_erc: ['erc20'],
			  logo_url:
				'https://logos.covalenthq.com/tokens/0x7ceb23fd6bc0add59e62ac25578270cff1b9f619.png',
			  contract_display_name: 'Wrapped Ether',
			  logo_urls: {
				token_logo_url:
				  'https://logos.covalenthq.com/tokens/0x7ceb23fd6bc0add59e62ac25578270cff1b9f619.png',
				protocol_logo_url: null,
				chain_logo_url: 'https://logos.covalenthq.com/chains/1.png',
			  },
			  list_transferred_at: '1700000000',
			  native_token: false,
			  type: 'cryptocurrency',
			  is_spam: false,
			  balance: '0.2',
			  balance_24h: '0.2',
			  quote_rate: '2003.2',
			  quote_rate_24h: '2003.2',
			  quote: '400.64',
			  pretty_quote: '$400.64',
			  quote_24h: '400.64',
			  pretty_quote_24h: '$400.64',
			  nft_data: [] as TokenNftData[],
			},
			{
			  contract_decimals: 6,
			  contract_name: 'Tether USD',
			  contract_ticker_symbol: 'USDT',
			  contract_address: '0x2791bca1f2de4661ed88a30c99a7a9449aa84174',
			  supports_erc: ['erc20'],
			  logo_url:
				'https://logos.covalenthq.com/tokens/0x2791bca1f2de4661ed88a30c99a7a9449aa84174.png',
			  contract_display_name: 'Tether USD',
			  logo_urls: {
				token_logo_url:
				  'https://logos.covalenthq.com/tokens/0x2791bca1f2de4661ed88a30c99a7a9449aa84174.png',
				protocol_logo_url: null,
				chain_logo_url: 'https://logos.covalenthq.com/chains/1.png',
			  },
			  list_transferred_at: '1700000000',
			  native_token: false,
			  type: 'stablecoin',
			  is_spam: false,
			  balance: '200',
			  balance_24h: '200',
			  quote_rate: '1.0',
			  quote_rate_24h: '1.0',
			  quote: '200.0',
			  pretty_quote: '$200.0',
			  quote_24h: '200.0',
			  pretty_quote_24h: '$200.0',
			  nft_data: [] as TokenNftData[],
			},
		  ],
		},
	  ];

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)

	  mockStytchClient.handleProviderOauth.mockResolvedValue(
		mockProviderAuthValue,
	  );

	  mockLitClient.generateProviderAuthMethod.mockResolvedValue({
		authMethod: { authMethodType: 9, accessToken: 'sample_access_token' },
		authId: 'mock_authId',
	  });

	  mockLitClient.getPubKeysFromAuthMethod.mockReturnValue(
		Promise.resolve({
		  tokenIds: mockPublicKeys.map((pk) => pk.tokenId),
		  publicKeys: mockPublicKeys.map((pk) => pk.publicKey),
		  balances: mockCovalentData,
		}),
	  );

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPublicKeys[1],
	  );

	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });

	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.GOOGLE,
		  method_id: 'sample_method_id',
		  code: '000000',
		},
		'test22sample',
		req,
	  );

	  expect(result).toEqual(ethers.utils.computeAddress(mockPublicKeys[1].publicKey));
	});

	it('should return initial value incase of wallets with same balance', async () => {
	  const mockBalanceData = {
		'0x21c88d0B3904251601b1b3b20dDB9E97491DDaF2': [
		  {
			decimals: 18,
			name: 'Wrapped Ether',
			symbol: 'WETH',
			token_address: '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619',
			logo: '',
			native_token: false,
			is_spam: false,
			balance: '0.1',
			usd_price: '3239.14',
		  },
		  {
			decimals: 6,
			name: 'Tether USD',
			symbol: 'USDT',
			token_address: '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619',
			logo: '',
			native_token: false,
			is_spam: false,
			balance: '200',
			usd_price: '1',
		  },
		],
		'0xF420922a4C308953e28346A3e43268Ed7b975539': [
		  {
			decimals: 18,
			name: 'Wrapped Ether',
			symbol: 'WETH',
			token_address: '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619',
			logo: '',
			native_token: false,
			is_spam: false,
			balance: '0.1',
			usd_price: '3239.14',
		  },
		  {
			decimals: 6,
			name: 'Tether USD',
			symbol: 'USDT',
			token_address: '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619',
			logo: '',
			native_token: false,
			is_spam: false,
			balance: '200',
			usd_price: '1',
		  },
		],
	  };

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)

	  mockStytchClient.handleProviderOauth.mockResolvedValue(
		mockProviderAuthValue,
	  );

	  mockLitClient.generateProviderAuthMethod.mockResolvedValue({
		authMethod: { authMethodType: 9, accessToken: 'sample_access_token' },
		authId: 'mock_authId',
	  });

	  mockLitClient.getPubKeysFromAuthMethod.mockReturnValue(
		Promise.resolve({
		  tokenIds: mockPublicKeys.map((pk) => pk.tokenId),
		  publicKeys: mockPublicKeys.map((pk) => pk.publicKey),
		  balances: mockBalanceData,
		}),
	  );

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPublicKeys[0],
	  );

	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });

	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.GOOGLE,
		  method_id: 'sample_method_id',
		  code: '000000',
		},
		'test22sample',
		req,
	  );

	  // Public Key with index 0 should be returned;
	  expect(result).toEqual(ethers.utils.computeAddress(mockPublicKeys[0].publicKey));
	});

	it('should successfully return the pkp address for webauthn provider', async () => {
	  const mockWebAuthnRequest = {
		authenticatorData: 'DsF-4lPgwc3_FsQqSykRney48wPTZ9cM3sNWLZkDuUodAAAAAA',
		challenge: 'd13573c6-c6d9-4284-ba47-c3245bfa4f98',
		clientDataJSON:
		  'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZDEzNTczYzYtYzZkOS00Mjg0LWJhNDctYzMyNDViZmE0Zjk4Iiwib3JpZ2luIjoiaHR0cHM6Ly92aWFibGUtcG9ldGljLXNhdHlyLm5ncm9rLWZyZWUuYXBwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ',
		id: 'lJrJ-wOgb8vefNZRAPC8YaRkNLs',
		rawId: 'lJrJ-wOgb8vefNZRAPC8YaRkNLs',
		signature:
		  'MEUCIDe2eAk4Ifk0uJn3y-7ICDuhemAJ0BImfgLm3iYuIgb9AiEAwEQmjuze8t0_GJxekDchriYa7Vbd2B10tgVkyQHBUy8',
		realProvider: Provider.GOOGLE,
	  };

	  const request = {
		...mockInputParams,
		provider: Provider.WEBAUTHN,
		webauthn: mockWebAuthnRequest,
	  };

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)
	  mockWebAuthnProvider.verifyAuthentication.mockResolvedValueOnce(
		'example@example.com',
	  );

	  mockLitClient.generateProviderAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );
	  mockAccountsRepository.findOneByKey.mockResolvedValue(null);
	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });

	  const result = await service.authenticate(request, 'test22sample', req);
	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should successfully register for webauthn provider', async () => {
	  const mockWebAuthnRequest = {
		attestationObject:
		  'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYDsF-4lPgwc3_FsQqSykRney48wPTZ9cM3sNWLZkDuUpdAAAAAPv8MAcVTk7MjAtuAgVX170AFJSayfsDoG_L3nzWUQDwvGGkZDS7pQECAyYgASFYIPh_T_W7lAMQfLwmiWxNNqoc0W33JEvlafV9JRoh6qFqIlggSt4_mVdMGmwkO6wfFKvFj4kXFTqRjVgkLnNkujW4YTs',
		authenticatorData:
		  'DsF-4lPgwc3_FsQqSykRney48wPTZ9cM3sNWLZkDuUpdAAAAAPv8MAcVTk7MjAtuAgVX170AFJSayfsDoG_L3nzWUQDwvGGkZDS7pQECAyYgASFYIPh_T_W7lAMQfLwmiWxNNqoc0W33JEvlafV9JRoh6qFqIlggSt4_mVdMGmwkO6wfFKvFj4kXFTqRjVgkLnNkujW4YTs',
		challenge: '533aa676-a36e-495d-8f50-2db68d468c50',
		clientDataJSON:
		  'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNTMzYWE2NzYtYTM2ZS00OTVkLThmNTAtMmRiNjhkNDY4YzUwIiwib3JpZ2luIjoiaHR0cHM6Ly92aWFibGUtcG9ldGljLXNhdHlyLm5ncm9rLWZyZWUuYXBwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ',
		id: 'lJrJ-wOgb8vefNZRAPC8YaRkNLs',
		rawId: 'lJrJ-wOgb8vefNZRAPC8YaRkNLs',
		wallet_address: 'example@example.com',
	  };

	  mockAccountsRepository.findOneByKey.mockResolvedValue(true);
	  mockWebAuthnProvider.verifyRegistration.mockResolvedValueOnce(true);

	  expect(
		await service.registerWithWebAuthn(req, mockWebAuthnRequest),
	  ).toEqual(true);
	});

	it('should throw an error if the passkey is not found for webauthn provider in authentication reqeust', async () => {
	  const mockWebAuthnRequest = {
		authenticatorData: 'DsF-4lPgwc3_FsQqSykRney48wPTZ9cM3sNWLZkDuUodAAAAAA',
		challenge: 'd13573c6-c6d9-4284-ba47-c3245bfa4f98',
		clientDataJSON:
		  'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZDEzNTczYzYtYzZkOS00Mjg0LWJhNDctYzMyNDViZmE0Zjk4Iiwib3JpZ2luIjoiaHR0cHM6Ly92aWFibGUtcG9ldGljLXNhdHlyLm5ncm9rLWZyZWUuYXBwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ',
		id: 'lJrJ-wOgb8vefNZRAPC8YaRkNLs',
		rawId: 'lJrJ-wOgb8vefNZRAPC8YaRkNLs',
		signature:
		  'MEUCIDe2eAk4Ifk0uJn3y-7ICDuhemAJ0BImfgLm3iYuIgb9AiEAwEQmjuze8t0_GJxekDchriYa7Vbd2B10tgVkyQHBUy8',
		realProvider: Provider.GOOGLE,
	  };

	  const request = {
		...mockInputParams,
		provider: Provider.WEBAUTHN,
		webauthn: mockWebAuthnRequest,
	  };

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPassKeyRepository.findOneByKey.mockResolvedValue(null);

	  await expect(
		service.authenticate(request, 'test22sample', req),
	  ).rejects.toThrowError();
	});

	it('should successfully authenticate user with telegram', async () => {
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)

	  mockTelegramAuthProvider.verify.mockResolvedValue(true);

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(
		mockPkpPublicKeys,
	  );

	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });

	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });

	  mockLitClient.callLitAction.mockResolvedValue({
		signatures: {
		  sig1: {
			signature: '0xtestsignature',
		  },
		},
		response: { message: 'signed_message' },
	  });

	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.TELEGRAM,
		  telegram_session: mockTelegramAuthDto,
		},
		'test22sample_apihash',
		req,
	  );

	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should claim a new pkp address for a user with telegram', async () => {
	  const mockNewPkpPublicKeys = {
		pkpAddress: ethers.utils.computeAddress(
		  '0x0432269de9b27eb6b2ceb62a421f25f71f8112951857abc17593981e8567a6d6aa5d89678be598c862b7e63e9d50f52d7c80a6d7b42bd51c26ae56873de188aa35',
		),
		pkpPublicKey:
		  '0x0432269de9b27eb6b2ceb62a421f25f71f8112951857abc17593981e8567a6d6aa5d89678be598c862b7e63e9d50f52d7c80a6d7b42bd51c26ae56873de188aa35',
		tokenId: '0xsample',
		signingPermissions: {
		  litAction: true,
		  customAuth: true,
		  stytch: true,
		},
	  };

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockPlatformAuthClient.verifyRequest.mockResolvedValueOnce(mockAuthMethodResponse)

	  mockTelegramAuthProvider.verify.mockResolvedValueOnce(true);

	  mockLitClient.getPubKeysFromAuthMethod.mockResolvedValue(null);

	  mockLitClient.claimKeyId.mockResolvedValueOnce(mockNewPkpPublicKeys);

	  mockAccountsRepository.findOneByKey.mockResolvedValue({
		...fetchedAccount,
		claimed: true,
	  });

	  mockLitClient.getSessionSigs.mockResolvedValue({
		sig: 'sample_sig',
		derivedVia: 'test',
		signedMessage: 'test_signed_message',
		address: '0x00000',
		algo: 'test_algo',
	  });

	  mockLitClient.callLitAction.mockResolvedValue({
		signatures: {
		  sig1: {
			signature: '0xtestsignature',
		  },
		},
		response: { message: 'signed_message' },
	  });

	  const result = await service.authenticate(
		{
		  ...mockInputParams,
		  provider: Provider.TELEGRAM,
		  telegram_session: mockTelegramAuthDto,
		},
		'test22sample_apihash',
		req,
	  );

	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	  expect(mockLitClient.claimKeyId).toHaveBeenCalled();
	});

	it('should throw an error if the request is pass the valid time', async () => {
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  // mock Implement TelegramClient.verify to just check for the auth_date
	  mockTelegramAuthProvider.verify.mockImplementationOnce(
		(authData: TelegramAuthDto) => {
		  if (authData.auth_date * 1000 < Date.now() - 5 * 60 * 1000) {
			throw new Error('Invalid auth_date');
		  }
		  return true;
		},
	  );

	  await expect(
		service.authenticate(
		  {
			...mockInputParams,
			provider: Provider.TELEGRAM,
			telegram_session: {
			  ...mockTelegramAuthDto,
			  auth_date: Date.now() / 1000 - 24 * 60 * 60,
			},
		  },
		  'test22sample_apihash',
		  req,
		),
	  ).rejects.toThrowError();
	});

	it('should throw an error if verification fails', async () => {
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  mockTelegramAuthProvider.verify.mockResolvedValueOnce(false);

	  await expect(
		service.authenticate(
		  {
			...mockInputParams,
			provider: Provider.TELEGRAM,
			telegram_session: mockTelegramAuthDto,
		  },
		  'test22sample_apihash',
		  req,
		),
	  ).rejects.toThrowError();
	});

	it('should throw an error if the telegram auth data is incomplete', async () => {
	  const incompleteTelegramAuthDto = {
		id: '123',
		auth_date: Date.now() / 1000,
		first_name: 'test',
		// hash missing
	  };

	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  await expect(
		service.authenticate(
		  {
			...mockInputParams,
			provider: Provider.TELEGRAM,
			telegram_session: incompleteTelegramAuthDto,
		  },
		  'test22sample_apihash',
		  req,
		),
	  ).rejects.toThrowError();
	});

	// TESTS FOR NATIVE AUTHENTICATION
	const mockGetPublicKeyDto: GetPubKeyDto = {
	  ...mockInputParams,
	};

	const mockAuthMethodResponse: AuthMethodResponseObject = {
	  authMethod: {
		authMethodType: AuthMethodType.Google,
		accessToken: mockInputParams.authKey,
	  },
	  authId: 'mock_authId',
	  profile_picture_url: 'https://test.example.com/profile_pic.png',
	  primary_contact: 'email@example.com',
	};

	it('should return a pkpaddress string for native auth', async () => {
	  // mock api key response
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  mockNativeAuthClient.hasNativeAuthEnabled.mockResolvedValueOnce(true);

	  // mock verification of request
	  mockNativeAuthClient.verifyRequest.mockResolvedValue(
		mockAuthMethodResponse,
	  );

	  const result = await service.authenticate(
		mockGetPublicKeyDto,
		'test22sample',
		req,
	  );

	  expect(result).toEqual(ethers.utils.computeAddress(mockPkpPublicKeys.publicKey));
	});

	it('should throw error if provider is not supported', async () => {
	  // mock api key response
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);

	  mockNativeAuthClient.hasNativeAuthEnabled.mockResolvedValueOnce(true);

	  // mock verification of request
	  mockNativeAuthClient.verifyRequest.mockRejectedValue(
		new Error('Invalid Provider'),
	  );

	  await expect(
		service.authenticate(mockGetPublicKeyDto, 'test22sample', req),
	  ).rejects.toThrowError();
	});
  });

  describe('send-transaction', () => {
	const mockTransactionRequest: TransactionsOperationDto = {
	  wallet_address: '0x1cD4147AF045AdCADe6eAC4883b9310FD286d95a',
	  transaction: {
		to: '0x1cD4147AF045AdCADe6eAC4883b9310FD286d95a',
		value: 0,
	  },
	  sessionKey: 'client_session_key',
	  chainId: 80001,
	};

	const mockExistingAccount = {
	  _id: { $oid: '660177398b3c898d586d1ade' },
	  key: 'x-test22',
	  pkpAddress: '0x02bf3Fb307806A771e920B4bC343Ea08739b48e2',
	  publicKey:
		'0x043ccfda21b75d1a20f4a2e4128f88273fdbb5c0a40c629062edc91b79d0bba9416b0840def9a1d65afff2d110934de3b4433de6bc40d835f2e7f853b80127953d',
	  keyId:
		'0x443b0b530a5c36d3352c3b4bec72c3e1f0cfa24a190d839c55025862a20e6082',
	  userId: 'e65c88de-605b-4b10-9968-105008f416cc',
	  authProvider: 'x',
	  litAuthId: null,
	  tokenId: 'test22',
	  claimed: false,
	  accountType: 'resolved',
	  createdAt: { $numberDouble: '1711372089799.0' },
	  updatedAt: { $numberDouble: '1711372089799.0' },
	  __v: { $numberInt: '0' },
	};
	it('should throw error if account not found', async () => {
	  mockAccountsRepository.findOneByKey.mockResolvedValue(null);
	  await expect(
		service.sendUserTransactions(mockTransactionRequest),
	  ).rejects.toThrowError();
	});

	it('should throw error if account not claimed', async () => {
	  mockAccountsRepository.findOneByKey.mockResolvedValue(
		mockExistingAccount,
	  );
	  await expect(
		service.sendUserTransactions(mockTransactionRequest),
	  ).rejects.toThrowError();
	});
  });

  describe('poll-session', () => {
	const mockExistingAccount = {
	  _id: { $oid: '660177398b3c898d586d1ade' },
	  pkpAddress: '0x02bf3Fb307806A771e920B4bC343Ea08739b48e2',
	  publicKey:
		'0x043ccfda21b75d1a20f4a2e4128f88273fdbb5c0a40c629062edc91b79d0bba9416b0840def9a1d65afff2d110934de3b4433de6bc40d835f2e7f853b80127953d',
	  keyId:
		'0x443b0b530a5c36d3352c3b4bec72c3e1f0cfa24a190d839c55025862a20e6082',
	  userId: 'e65c88de-605b-4b10-9968-105008f416cc',
	  authProvider: 'x',
	  user: {
		first_name: 'first_name',
		last_name: 'last_name',
		middle_name: 'middle_name',
		email: 'test@gmail.com',
	  },
	  litAuthId: null,
	  tokenId: 'test22',
	  claimed: false,
	  accountType: 'resolved',
	  createdAt: { $numberDouble: '1711372089799.0' },
	  updatedAt: { $numberDouble: '1711372089799.0' },
	  __v: { $numberInt: '0' },
	};

	const mockApiResponse = {
	  _id: { $oid: '66058faf77016870a7026170' },
	  createdAt: { $numberDouble: '1711640495995.0' },
	  updatedAt: { $numberDouble: '1711640495995.0' },
	  apiKey:
		'bbf657c9a9976d1b0bd6ea823cf33be4b9a961ba126bf6742331ac85b5cf53dc',
	  projectName: 'platform_test_oa',
	  userId: { $oid: '660519aeffff7ab36de4dec5' },
	  __v: { $numberInt: '0' },
	};

	const mockSession = {
	  _id: { $oid: '660598e55ac85880a9c71c28' },
	  accountId: { $oid: '660598df5ac85880a9c71c25' },
	  sessionSigs: {
		'1.1.1.1': {
		  sig: '4082223348b894aa963af171d55960061e9a5d484b4f02d044bf34c4b3df145e191e22dca4b5d7f56fb08a95738b9cc3c4811adffbafb03a9585dcf447a54d0c',
		  derivedVia: 'litSessionSignViaNacl',
		  signedMessage:
			'{"sessionKey":"f06c66f16f920a6a1fd36e625ea6b062e2d9ac785cb24a7a99b2012ebe23d16e","resourceAbilityRequests":[{"resource":{"resource":"*","resourcePrefix":"lit-litaction"},"ability":"pkp-signing"}],"capabilities":[{"sig":"0xe82736e3829e3381d5b5e53e375968e92eed657b130c5608e96231f5da2f3b4503d3a6c3d2c0d5eca66847f9be8e23164cbb2b4d86bf3562ab38415c9142bc851c","derivedVia":"web3.eth.personal.sign via Lit PKP","signedMessage":"litprotocol.com wants you to sign in with your Ethereum account:\\n0xC223Ee743c07C91c826811c32b43F79A896C44c5\\n\\nLit Protocol PKP session signature I further authorize the stated URI to perform the following actions on my behalf:\\n\\nURI: lit:session:f06c66f16f920a6a1fd36e625ea6b062e2d9ac785cb24a7a99b2012ebe23d16e\\nVersion: 1\\nChain ID: 1\\nNonce: 0xc0d075991effce772800ea565052e9a8f85d18da9350a605397e5c1100836cb3\\nIssued At: 2024-03-28T16:20:11Z\\nExpiration Time: 2024-03-29T16:20:47.170Z\\nResources:\\n- urn:recap:eyJhdHQiOnt9LCJwcmYiOltdfQ","address":"0xC223Ee743c07C91c826811c32b43F79A896C44c5"}],"issuedAt":"2024-03-28T16:20:52.915Z","expiration":"2024-03-28T16:25:52.915Z","nodeAddress":"https://cayenne.litgateway.com:7370"}',
		  address:
			'f06c66f16f920a6a1fd36e625ea6b062e2d9ac785cb24a7a99b2012ebe23d16e',
		  algo: 'ed25519',
		},
	  },
	  expiresAt: { $date: { $numberLong: '1711729247170' } },
	  createdAt: { $numberDouble: '1711642853000.0' },
	  updatedAt: { $numberDouble: '1711642853000.0' },
	  user: {
		first_name: 'first_name',
		last_name: 'last_name',
		middle_name: 'middle_name',
		primary_contact: 'test@gmail.com',
	  },
	  accessControlConditions: {
		origin: 'test',
		agent: 'test',
		referer: 'test',
	  },
	  wallet_address: '0xtest',
	  session_identifier: 'test22sample',
	  apiKeyId: '66058faf77016870a7026170',
	  __v: { $numberInt: '0' },
	};

	const mockParams: PollSession = {
	  provider: Provider.X,
	  session_identifier: 'test22',
	};

	it('should throw error if session not found', async () => {
	  mockSessionsRepository.findOne.mockResolvedValue(null);
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  await expect(
		service.pollSessionSigs(mockParams),
	  ).rejects.toThrowError();
	});

	it('should throw error if session expired', async () => {
	  mockSessionsRepository.findOne.mockResolvedValue({
		...mockSession,
		createdAt: Date.now() - 24 * 60 * 60 * 1000,
	  });
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  await expect(
		service.pollSessionSigs(mockParams),
	  ).rejects.toThrowError();
	});

	it('should return clientSessionKey', async () => {
	  mockSessionsRepository.findOne.mockResolvedValue(mockSession);
	  mockApiKeysRepository.findOne.mockResolvedValue(mockApiResponse);
	  mockSessionsRepository.updateSession.mockResolvedValue(null);

	  // mock jwt sign
	  const mockJwtToken = 'mockJwtToken';

	  (jwt.sign as jest.Mock).mockReturnValue(mockJwtToken);

	  const result = await service.pollSessionSigs(
		mockParams,
	  );

	  expect(result).toEqual({
		user: {
		  first_name: 'first_name',
		  last_name: 'last_name',
		  middle_name: 'middle_name',
		  primary_contact: 'test@gmail.com',
		},
		wallet_address: '0xtest',
		key: mockJwtToken,
	  });
	});
  });

  describe('external-wallet', () => {
	it('should throw error if address not valid', async () => {
	  await expect(
		service.addExternalWallet(
		  {
			address: '0xsample',
			message: 'Welcome to Open Auth',
			walletType: 'Metamask',
			signature: 'something',
		  },
		),
	  ).rejects.toThrowError();
	});
  });

  describe('addCredentials', () => {
	const mockGoogleCredentials = {
	  client_id: 'sample_client_id',
	  client_secret: 'sample_client_secret',
	};

	const apiKeyHash = 'sample_api_key_hash';

	const mockInputParams: AuthProvidersDto = {
	  provider: Provider.GOOGLE,
	  credentials: mockGoogleCredentials,
	};

	it('should add credentials for google provider', async () => {
	  mockOAuthClientDataRepository.addOrUpdateClientData.mockResolvedValue({
		_id: 'mock_id',
		provider: Provider.GOOGLE,
		client_id: 'sample_client_id',
		client_secret: 'sample_client_secret',
	  });

	  await service.addCredentials(mockInputParams, apiKeyHash);

	  expect(mockNativeAuthClient.registerCredentials).toHaveBeenLastCalledWith(
		Provider.GOOGLE,
		apiKeyHash,
		{
		  client_id: 'sample_client_id',
		  client_secret: 'sample_client_secret',
		},
	  );
	});
  });

  describe('getClientCallbackUrl', () => {
	const apiKeyHash = 'mock_api_key_hash';

	it('should return client callback url for provider google', async () => {
	  mockOAuthClientDataRepository.findOneByKey.mockResolvedValue({
		_id: 'mock_id',
		provider: Provider.GOOGLE,
		client_id: 'sample_client_id',
		client_secret: 'sample_client_secret',
	  });

	  mockNativeAuthClient.getCallbackUrl.mockImplementationOnce(
		() => 'https://authenticate.google.com?client_id=sample_client_id',
	  );

	  const result = await service.getClientCallbackUrl(
		Provider.GOOGLE,
		apiKeyHash,
	  );

	  expect(result).toBeDefined();
	  expect(result).not.toEqual('');

	  expect(result).toContain('sample_client_id');
	});
  });
});
