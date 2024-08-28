# Service Open Auth Backend

[![Discord](https://img.shields.io/badge/Discord-Join%20Chat-7289DA?style=flat&logo=discord&logoColor=white)](https://discord.gg/3kFCfBgSdY) [![Telegram](https://img.shields.io/badge/Telegram-Join%20Chat-blue?style=flat&logo=telegram)](https://t.me/aarcxyz)

A backend service for OpenAuth, providing necessary APIs for user registration, login, authentication, and integration with blockchain protocols and other services.

## Table of Contents

- [Service Open Auth Backend](#service-open-auth-backend)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Development](#development)
    - [Production](#production)
  - [Project Structure](#project-structure)
  - [Environment Variables](#environment-variables)
    - [Required Variables](#required-variables)
    - [Blockchain RPC URLs](#blockchain-rpc-urls)
  - [Contributing](#contributing)

## Overview

The Service Open Auth Backend is a crucial component of the OpenAuth ecosystem, handling server-side operations for authentication and blockchain interactions.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/aarc-xyz/service-open-auth-backend.git
    cd service-open-auth-backend
    ```

2. Install dependencies:
    ```sh
    npm install
    ```

3. Set up environment variables:
    ```sh
    cp .env.example .env
    ```
   Edit the `.env` file with your specific configuration. See [Environment Variables](#environment-variables) for details.

4. Build the project:
    ```sh
    npm run build
    ```

## Usage

### Development

To start the development server with hot-reloading:

```sh
npm run start:dev
```

### Production

To start the production server:

```sh
npm run start:prod
```

## Project Structure

- **src/**
  - **modules/open-auth/**: OpenAuth module (controllers, services, etc.)
  - **abis/**: ABI files for blockchain contract interactions
  - **main.ts**: Application entry point
- **test/**: End-to-end tests

## Environment Variables

### Required Variables

| Variable | Description | How to Obtain |
|----------|-------------|---------------|
| `DB_URL` | MongoDB connection string | [MongoDB Atlas](https://www.mongodb.com/docs/atlas/tutorial/connect-to-your-cluster/) |
| `LOGGER_ENV` | Logging flag | Set manually |
| `OPENAUTH_SERVICE_PORT` | Service port | Set manually |
| `PLATFORM_CUSTOM_AUTH_SALT` | Custom auth salt | Generate securely |
| `STYTCH_PROJECT_ID` | Stytch project ID | [Stytch Dashboard](https://stytch.com/dashboard) |
| `STYTCH_SECRET` | Stytch secret key | [Stytch Dashboard](https://stytch.com/dashboard) |
| `LIT_API_KEY` | Lit Protocol API key | [Lit Protocol Dashboard](https://developer.litprotocol.com/) |
| `LIT_CHRONICLE_YELLOWSTONE_RPC` | Lit Protocol RPC URL | [Lit Documentation](https://developer.litprotocol.com/docs/intro) |
| `LIT_CONTROLLER_PRIVATE_KEY` | Lit Protocol private key | Generate securely |
| `LIT_CREDITS_TOKENID` | Lit Protocol token ID | [Lit Documentation](https://developer.litprotocol.com/docs/intro) |
| `TWILIO_ACCOUNT_SID` | Twilio account SID | [Twilio Console](https://www.twilio.com/console) |
| `TWILIO_ACCOUNT_SECRET_AUTH_TOKEN` | Twilio auth token | [Twilio Console](https://www.twilio.com/console) |
| `TWILIO_SERVICE_ID` | Twilio service ID | [Twilio Console](https://www.twilio.com/console) |
| `X_OAUTH_CALLBACK` | OAuth callback URL | Set manually |
| `X_OAUTH_CONSUMER_KEY` | Twitter OAuth consumer key | [Twitter Developer Portal](https://developer.twitter.com/en/portal/dashboard) |
| `X_OAUTH_CONSUMER_SECRET` | Twitter OAuth consumer secret | [Twitter Developer Portal](https://developer.twitter.com/en/portal/dashboard) |
| `PLATFORM_AUTH_VALIDATION_URL` | Auth validation URL | Set manually |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | [BotFather on Telegram](https://core.telegram.org/bots#6-botfather) |

### Blockchain RPC URLs

Obtain free RPC URLs from providers like Ankr. Required for various blockchain networks:

- `ETH_MAINNET_RPC_URL`
- `ETH_GOERLI_RPC_URL`
- `ETH_SEPOLIA_RPC_URL`
- `POLYGON_MAINNET_RPC_URL`
- `POLYGON_AMOY_RPC_URL`
- `POLYGON_ZKEVM_MAINNET_RPC_URL`
- `ARBITRUM_RPC_URL`
- `ARBITRUM_SEPOLIA_RPC_URL`
- `ARBITRUM_GOERLI_RPC_URL`
- `OPTIMISM_MAINNET_RPC_URL`
- `BASE_MAINNET_RPC_URL`
- `BASE_TESTNET_RPC_URL`
- `BSC_MAINNET_RPC_URL`
- `BSC_TESTNET_RPC_URL`
- `AVALANCHE_MAINNET_RPC_URL`
- `AVALANCHE_FUJI_RPC_URL`
- `LINEA_MAINNET_RPC_URL`
- `LINEA_TESTNET_RPC_URL`

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) for details on how you can help improve the Service Open Auth Backend.

For more detailed information or support, please reach out through our [Discord](https://discord.gg/3kFCfBgSdY) or [Telegram](https://t.me/aarcxyz) channels.