import {
  Injectable,
  Logger,
  ExecutionContext,
  CanActivate,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'node:crypto';
import { SessionsRepository } from '../../open-auth/repositories/sessions.repository';
import {
  AccessControlConditions,
  SessionsDocument,
} from '../../open-auth/entities/Sessions.entity';
import { PLATFORM_AUTH_VALIDATION_URL } from '../common/constants';
import { generateAuthConditions } from '../common/helpers';

@Injectable()
export class AccessValidationGuard implements CanActivate {
  private readonly logger: Logger = new Logger(AccessValidationGuard.name);
  constructor(private readonly sessionRepository: SessionsRepository) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const walletAddress = request.body.wallet_address;

    const origin = request.headers['origin'];
    const userAgent = request.headers['user-agent'];
    // custom header for validation during /authenticate request
    const requestSource = request.headers['request-source'];

    if (!origin) {
      this.logger.error('Origin not passed');
      throw new BadRequestException('Origin not passed');
    }

    if (!userAgent) {
      this.logger.error('User-Agent not passed');
      throw new BadRequestException('User-Agent not passed');
    }

    const requestType = request.route.path.split('/')[1];
    if (requestType === 'authenticate') {
      // compare origin with PLATFORM_AUTH_VALIDATION_URL, remove any trailing slashes
      const platformValidationUrl: string = PLATFORM_AUTH_VALIDATION_URL.replace(
        /\/$/,
        '',
      );

      const originUrl = origin.replace(/\/$/, '');

      if (originUrl === platformValidationUrl) {
        if (!requestSource) {
          this.logger.error('Request source not passed');
          throw new BadRequestException('Request source not passed');
        }

        request.body.accessControlConditions = {
          origin: requestSource,
          agent: userAgent,
        };
        return true;
      }

      request.body.accessControlConditions = {
        origin: origin,
        agent: userAgent,
      };

      return true;
    }

    if (requestType === 'poll-session') {
      const session_identifier = request.params.session_identifier;
      if (!session_identifier) {
        this.logger.error('Session identifier not passed');
        throw new BadRequestException('Session identifier not passed');
      }

      const session = await this.sessionRepository.findOne({
        session_identifier: session_identifier,
      });

      if (!session) {
        throw new UnauthorizedException('Session not found');
      }

      const accessControlConditions: AccessControlConditions =
        session.accessControlConditions;
      if (!accessControlConditions) {
        this.logger.error('Failed to find access conditions');
        throw new UnauthorizedException('Invalid request source, unauthorized');
      }

      const hash: string = generateAuthConditions({
        origin: origin,
        agent: userAgent,
      });
      const expectedHash: string = generateAuthConditions(
        accessControlConditions,
      );

      if (hash !== expectedHash) {
        this.logger.error('Invalid request source, unauthorized');
        throw new UnauthorizedException('Invalid request source, unauthorized');
      }
      return true;
    }

    const hash: string = generateAuthConditions({
      origin: origin,
      agent: userAgent,
    });
    const session: SessionsDocument = await this.sessionRepository.findOne({
      wallet_address: walletAddress,
    });

    if (!session) {
      throw new UnauthorizedException('Session not found');
    }

    const accessControlConditions: AccessControlConditions =
      session.accessControlConditions;
    if (!accessControlConditions) {
      this.logger.error('Failed to find access conditions');
      throw new UnauthorizedException('Invalid request source, unauthorized');
    }
    const expectedHash: string = generateAuthConditions(
      accessControlConditions,
    );

    if (hash !== expectedHash) {
      this.logger.error('Invalid request source, unauthorized');
      throw new UnauthorizedException('Invalid request source, unauthorized');
    }
    return true;
  }
}
