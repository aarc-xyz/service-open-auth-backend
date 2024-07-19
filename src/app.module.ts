import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { OpenAuthModule } from "./modules/open-auth/open-auth.module";
import { MongooseModule } from "@nestjs/mongoose";
import * as dotenv from "dotenv";
import { DB_URL } from "./constants";

dotenv.config();

@Module({
  imports: [
      MongooseModule.forRoot(DB_URL),
      OpenAuthModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
