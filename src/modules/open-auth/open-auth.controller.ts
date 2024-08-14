import {
  Body,
  Controller,
  Get,
  Headers,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  Res, UseGuards
} from "@nestjs/common";
import { ethers } from 'ethers';
import { Request, Response } from "express";
import {
  ExternalWalletDto,
  GetPubKeyDto, RegisterWebAuthnDto,
} from "./dto/Accounts.dto";
import { PollSession } from './dto/Sessions.dto';
import {
  SignMessageDto,
  TransactionsOperationDto,
} from './dto/Transactions.dto';
import { OpenAuthService } from './open-auth.service';
import { AccessValidationGuard } from "./guards/AccessValidation.guard";
import { Provider } from "./common/types";
import { AuthProvidersDto } from "./dto/AuthProviders.dto";

@Controller()
export class OpenAuthController {
  constructor(
    private readonly openAuthService: OpenAuthService,
  ) {}

  @Get('')
  getHealth(): string {
    return 'open-auth is up and running';
  }

  @Post('add-credentials')
  async addCredentials(
    @Body() addAuthProviderDto: AuthProvidersDto,
    @Req() req: Request,
    @Headers() headers: Record<string, string>,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const keyHash = headers['x-api-key'];
      await this.openAuthService.addCredentials(addAuthProviderDto, keyHash);
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
        code: HttpStatus.UNPROCESSABLE_ENTITY,
        message: 'Failed to add credentials',
      });
    }
  }

  @Get('callback-url/:provider')
  async getCallBackUrl(
    @Param() params: { provider: Provider },
    @Query() query: { state: string },
    @Req() req: Request,
    @Headers() headers: Record<string, string>,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const keyHash = headers['x-api-key'];
      const callbackUrl = await this.openAuthService.getClientCallbackUrl(
        params.provider,
        query.state,
        keyHash,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: callbackUrl,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
        code: HttpStatus.UNPROCESSABLE_ENTITY,
        message: 'Failed to generate callback url',
      });
    }
  }

  @UseGuards(AccessValidationGuard)
  @Post('authenticate')
  async authenticate(
    @Req() req: Request,
    @Headers() headers: Record<string, string>,
    @Body() getPubKey: GetPubKeyDto,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const keyHash = headers['x-api-key'];
      const response = await this.openAuthService.authenticate(
        getPubKey,
        keyHash,
        req,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        code: HttpStatus.BAD_REQUEST,
        data: error.data,
        message: error.name,
      });
    }
  }

  @UseGuards(AccessValidationGuard)
  @Post('sign-message')
  async signMessage(
    @Req() req: Request,
    @Body() signMessageDto: SignMessageDto,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const signedMessage = await this.openAuthService.signUserMessage(
        signMessageDto,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: signedMessage,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
        code: HttpStatus.UNPROCESSABLE_ENTITY,
        data: error.data,
        message: error.name,
      });
    }
  }

  @UseGuards(AccessValidationGuard)
  @Post('sign-transaction')
  async signTransaction(
    @Req() req: Request,
    @Body() signTransactionDto: TransactionsOperationDto,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const signedTx = await this.openAuthService.signUserTransactions(
        signTransactionDto,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: signedTx,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
        code: HttpStatus.UNPROCESSABLE_ENTITY,
        data: error.data,
        message: error.name,
      });
    }
  }

  @UseGuards(AccessValidationGuard)
  @Post('send-transaction')
  async sendTransaction(
    @Req() req: Request,
    @Body() transaction: TransactionsOperationDto,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const txn = await this.openAuthService.sendUserTransactions(transaction);
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: txn,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
        code: HttpStatus.UNPROCESSABLE_ENTITY,
        data: error.data,
        message: error.name,
      });
    }
  }

  @Get('passcode/:mode/:contact')
  async passcode(
    @Req() req: Request,
    @Param() params: { mode: string; contact: string },
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const response = await this.openAuthService.otp_auth_code(
        params.contact,
        params.mode,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
        code: HttpStatus.UNPROCESSABLE_ENTITY,
        data: error.data,
        message: error.name,
      });
    }
  }

  @UseGuards(AccessValidationGuard)
  @Get('poll-session/:provider/:session_identifier')
  async poll_session(
    @Headers() headers: Record<string, string>,
    @Param() params: PollSession,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const keyHash = headers['x-api-key'];
      const response = await this.openAuthService.pollSessionSigs(
        {
          provider: params.provider,
          session_identifier: params.session_identifier,
        },
        keyHash,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        code: HttpStatus.BAD_REQUEST,
        data: error.data,
        message: error.name,
      });
    }
  }

  @Post('external-wallet')
  async addExternalWallet(
    @Req() req: Request,
    @Headers() headers: Record<string, string>,
    @Body() accountData: ExternalWalletDto,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const keyHash = headers['x-api-key'];
      const response = await this.openAuthService.addExternalWallet(
        accountData,
        keyHash,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        code: HttpStatus.BAD_REQUEST,
        data: error.data,
        message: error.name,
      });
    }
  }

  @Get('get-pkp-txns/:address')
  async get_pkp_txns(
    @Param() params: { address: string },
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const response = await this.openAuthService.getPkpTxns(
        ethers.utils.getAddress(params.address),
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        code: HttpStatus.BAD_REQUEST,
        data: error.data,
        message: error.name,
      });
    }
  }

  @Get('x-token')
  async get_x_req_token(
    @Query() query: { state: string },
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const response = await this.openAuthService.getTwitterRequestToken(
        query.state,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        code: HttpStatus.BAD_REQUEST,
        message: 'Failed to get X request token',
      });
    }
  }

  @Get('webauthn-register-options/:session_identifier')
  async getWebAuthnRegisterOptions(
    @Param() params: { session_identifier: string },
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const response =
        await this.openAuthService.generateWebAuthnRegistrationOpts(
          req,
          params.session_identifier,
        );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        code: HttpStatus.BAD_REQUEST,
        data: error.data,
        message: error.name,
      });
    }
  }

  @Post('register-webauthn')
  async registerWebAuthn(
    @Body() body: RegisterWebAuthnDto,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const response = await this.openAuthService.registerWithWebAuthn(
        req,
        body,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: response,
        message: 'success',
      });
    } catch (error) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        code: HttpStatus.BAD_REQUEST,
        data: error.data,
        message: error.name,
      });
    }
  }
}
