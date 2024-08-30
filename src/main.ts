import { NestFactory } from '@nestjs/core';
import { OPENAUTH_SERVICE_PORT, validateEnvironmentVariables } from "./constants";
import { OpenAuthModule } from "./modules/open-auth/open-auth.module";
import {ValidationPipe} from "@nestjs/common";

async function bootstrap() {
  validateEnvironmentVariables();

  const oaServiceApp = await NestFactory.create(OpenAuthModule, {
    logger: ['log', 'error'],
  });
  oaServiceApp.useGlobalPipes(new ValidationPipe({ transform: true }));
  oaServiceApp.enableCors();
  await oaServiceApp.listen(OPENAUTH_SERVICE_PORT);
}
bootstrap();
