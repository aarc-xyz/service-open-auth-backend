import { Logger } from '@nestjs/common';
import { AuthMethodResponseObject, Provider } from "../common/types";

export abstract class BaseAuthProvider {
  protected readonly logger: Logger;
  private readonly provider: Provider;

  protected constructor(provider: Provider, className: string) {
    this.logger = new Logger(className);
    this.provider = provider;
  }

  getProviderName(): string {
    return this.provider;
  }

  abstract registerCredentials(...args: Array<unknown>): Promise<void>;

  abstract generateCallbackUrl(id: string, state?: string): Promise<string>;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  abstract verify(...args: Array<unknown>): Promise<AuthMethodResponseObject | any>;
}