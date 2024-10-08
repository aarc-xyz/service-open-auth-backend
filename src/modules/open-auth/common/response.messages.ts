// message that would be returns as api responses
export const enum MESSAGES {
  SUCCESS = 'Success',
  FAILED = 'Request Failed',
  NOT_FOUND = 'Resource Not Found',
  NO_TRX_FOUND = 'No transaction found',
  NO_GAS_PRICE_FOUND = 'No gas price found',
  MISSING_PARAMS = 'Params are missing',
  SERVICE_TEMPORARY_DOWN = 'Service is temporary down',
  USER_ALREADY_EXIST = 'User with this email already exists',
  INCORRECT_SIGNATURE = 'Incorrect Signature',
  INVALID_SIGNATURE = 'Invalid Signature',
  INVALID_ADDRESS = 'Invalid Address',
  USER_NOT_FOUND = 'User Not Found',
  TRANSACTION_ALREADY_PROCESSED = 'Transaction already processed',
  TRANSACTION_NOT_FOUND = 'Transaction against provided hash not found',
  TRANSACTION_IS_NOT_VALID = 'Provided transaction does not belong to user',
  CHAIN_NOT_SUPPORTED = 'Chain not supported',
  NO_BALANCES_FOUND = 'No balances found',
  NO_TASK_ID = 'Missing task id',
  INSUFFICIENT_BALANCE = 'Not enough balance for transaction sponsorship',
  INSUFFICIENT_GAS_TOKEN_BALANCE = 'Insufficient gas token balance',
  TREASURY_TRANSACTION_MANUPULATED = 'Treasury transaction is manupulated',
  INVALID_TREASURY_ADDRESS = 'Invalid treasury address',
  NO_TX_LIST_FOUND = 'No Tx List Found',
  MISSING_TX_INDEXES = 'Missing tx Indexes',
  API_KEY_ALREADY_GENERATED = 'Api key already generated for this user',
  API_KEY_LIMIT_REACHED = 'Api key Limit Reached',
  WALLET_ADDRESS_ALREADY_EXIST = 'Wallet address already exist for some other user',
  API_KEY_VALIDATION_ERROR = 'Error validating API key',
  INVALID_TOKEN = 'Invalid token, authentication failed',
  INVALID_PARAMS = 'Invalid params, Either send email and accessToken Or walletAddress and signedMessaged',
  EXPIRED_SIGNATURE = 'Signature has expired, need a new signature',
  INVALID_NONCE = 'Invalid nonce, nonce does not match with the signed message',
}

export const BRIDGE_ROUTE_MESSAGES = {
  ASSET_NOT_SUPPORTED: 'ASSET_NOT_SUPPORTED',
  MIN_AMOUNT_NOT_SUPPORTED: 'MIN_AMOUNT_NOT_SUPPORTED',
};

export const ErrorMappings = {
  BSA012: 'Insufficient Token Balance',
};

export enum RESPONSE_CODES {
  Continue = 100,
  SwitchingProtocols = 101,
  Processing = 102,
  EarlyHints = 103,
  Ok = 200,
  Created = 201,
  Accepted = 202,
  NonAuthoritativeInformation = 203,
  NoContent = 204,
  ResetContent = 205,
  PartialContent = 206,
  MultiStatus = 207,
  AlreadyReported = 208,
  ImUsed = 226,
  MultipleChoices = 300,
  MovedPermanently = 301,
  Found = 302,
  SeeOther = 303,
  NotModified = 304,
  UseProxy = 305,
  Unused = 306,
  TemporaryRedirect = 307,
  PermanentRedirect = 308,
  BadRequest = 400,
  Unauthorized = 401,
  PaymentRequired = 402,
  Forbidden = 403,
  NotFound = 404,
  MethodNotAllowed = 405,
  NotAcceptable = 406,
  ProxyAuthenticationRequired = 407,
  RequestTimeout = 408,
  Conflict = 409,
  Gone = 410,
  LengthRequired = 411,
  PreconditionFailed = 412,
  PayloadTooLarge = 413,
  UriTooLong = 414,
  UnsupportedMediaType = 415,
  RangeNotSatisfiable = 416,
  ExpectationFailed = 417,
  ImATeapot = 418,
  MisdirectedRequest = 421,
  UnprocessableEntity = 422,
  Locked = 423,
  FailedDependency = 424,
  TooEarly = 425,
  UpgradeRequired = 426,
  PreconditionRequired = 428,
  TooManyRequests = 429,
  RequestHeaderFieldsTooLarge = 431,
  UnavailableForLegalReasons = 451,
  InternalServerError = 500,
  NotImplemented = 501,
  BadGateway = 502,
  ServiceUnavailable = 503,
  GatewayTimeout = 504,
  HttpVersionNotSupported = 505,
  VariantAlsoNegotiates = 506,
  InsufficientStorage = 507,
  LoopDetected = 508,
  NotExtended = 510,
  NetworkAuthenticationRequired = 511,
}
