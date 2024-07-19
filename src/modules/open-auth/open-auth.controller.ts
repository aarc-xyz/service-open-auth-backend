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
  Res,
} from '@nestjs/common';
import { ethers } from 'ethers';
import { Response } from 'express';
import {
  ClaimAccountDto,
  ExternalWalletDto,
  GetPubKeyDto,
  ResolveAccountDto,
} from './dto/Accounts.dto';
import { PollSession } from './dto/Sessions.dto';
import {
  SignMessageDto,
  TransactionsOperationDto,
} from './dto/Transactions.dto';
import { OpenAuthService } from './open-auth.service';

@Controller()
export class OpenAuthController {
  constructor(
    private readonly openAuthService: OpenAuthService,
  ) {}

  @Get('')
  getHealth(): string {
    return 'open-auth is up and running';
  }

  @Post('resolve')
  async resolveAccount(
    @Body() resolveAccountDto: ResolveAccountDto[],
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const pkpAddresses: string[] = await this.openAuthService.resolveAccount(
        resolveAccountDto,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: {
          pkpAddresses: pkpAddresses,
        },
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

  @Post('claim')
  async claimAccount(
    @Req() req: Request,
    @Body() claimAccountDto: ClaimAccountDto,
    @Res() res: Response,
  ): Promise<Response> {
    try {
      const transactionDetails = await this.openAuthService.claimAccount(
        claimAccountDto,
      );
      return res.status(HttpStatus.OK).json({
        code: HttpStatus.OK,
        data: transactionDetails,
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
}
