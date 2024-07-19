import * as dotenv from 'dotenv';

dotenv.config();

const HABANERO = 'habanero';
const CAYENNE = 'cayenne';

export const AARC_CUSTOM_AUTH_SALT = process.env.AARC_CUSTOM_AUTH_SALT;

export const STYTCH_PROJECT_ID = process.env.STYTCH_PROJECT_ID;
export const STYTCH_SECRET = process.env.STYTCH_SECRET;
export const STYTCH_EMAIL_METHOD_ID = '';
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const LIT_API_KEY = process.env.LIT_API_KEY;
export const CHRONICLE_RPC_URL = process.env.LIT_CHRONICLE_RPC;
export const LIT_CONTROLLER_PRIVATE_KEY =
  process.env.LIT_CONTROLLER_PRIVATE_KEY;
export const LIT_CONTROLLER_ADDRESS = process.env.LIT_CONTROLLER_ADDRESS;
export const LIT_CUSTOM_AUTH_TYPE_ID = 2092;
export const LIT_RELAY_URL = 'https://habanero-relayer.getlit.dev';
export const LIT_CREDITS_TOKENID = process.env.LIT_CREDITS_TOKENID;
export const SIWE_DELEGATION_URI = 'lit:capability:delegation';

// Open-Auth SessionSigs constants
export const derivedVia = 'litSessionSignViaNacl';
export const algo = 'ed25519';

// Lit action CID
export const LIT_CLAIM_KEY_ACTION_CID =
  'QmV2Ah6t3KKGzDW9q4ntGodmCzAP8RZE8wTHse1pfX1bbA';
export const LIT_ACTION_1_CID =
  //'QmY2F3dEi7JMJRJVVcXxQoc5TGcVJSBMF9ZKc8hPqSqxkj';
  'QmWKKDy8FPxAMeTUj88B47MWZkdtdw4HNZohepr6y7sUjC';

export const LIT_CLIENT_NETWORK = HABANERO;

export const pkpNft_CONTRACT_ADDRESS = {
  habanero: '0x80182Ec46E3dD7Bb8fa4f89b48d303bD769465B2',
  cayenne: '0x58582b93d978F30b4c4E812A16a7b31C035A69f7',
};

export const pkpHelper_CONTRACT_ADDRESS = {
  habanero: '0x087995cc8BE0Bd6C19b1c7A01F9DB6D2CfFe0c5C',
  cayenne: '0xF02b6D6b0970DB3810963300a6Ad38D8429c4cdb',
};

export const pkpPermissions_CONTRACT_ADDRESS = {
  habanero: '0x1B76BFAA063A35c88c7e82066b32eEa91CB266C6',
  cayenne: '0xD01c9C30f8F6fa443721629775e1CC7DD9c9e209',
};

// TWILIO TOKENS
export const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
export const TWILIO_ACCOUNT_SECRET_AUTH_TOKEN =
  process.env.TWILIO_ACCOUNT_SECRET_AUTH_TOKEN;
export const TWILIO_SERVICE_ID = process.env.TWILIO_SERVICE_ID;
export const BASE64_TWILIO_AUTH_TOKEN = process.env.BASE64_TWILIO_AUTH_TOKEN;
export const TWILIO_AUTH_BASE_URL = 'https://verify.twilio.com/v2/';

// FARCASTER CONSTANTS
export const FARCASTER_ID_REGISTRY_CONTRACT_ADDRESS =
  '0x00000000fc6c5f01fc30151999387bb99a9f489b';
export const FID_URI_REGEX = /^farcaster:\/\/fid\/([1-9]\d*)\/?$/;
export const VALID_STATEMENTS = ['Farcaster Connect', 'Farcaster Auth'];
export const VALID_CHAIN_ID = 10;

// TWITTER KEYS
export const X_API_BASE_URL = 'https://api.twitter.com';
export const X_OAUTH_CALLBACK = process.env.X_OAUTH_CALLBACK;
export const X_OAUTH_CONSUMER_KEY = process.env.X_OAUTH_CONSUMER_KEY;
export const X_OAUTH_CONSUMER_SECRET = process.env.X_OAUTH_CONSUMER_SECRET;
export const X_OAUTH_SIGNATURE_METHOD = 'HMAC-SHA1';
export const X_OAUTH_VERSION = '1.0';

// TELEGRAM BOT TOKEN
export const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
export const TELEGRAM_AUTH_VALID_DURATION = 5 * 60 * 1000; //5 minutes

// UTILS
export const LIT_CLIENT_TIMEOUT = 60 * 1000;
export const TIMESTAMP_REGEX = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/;
