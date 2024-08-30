import { Injectable, Logger } from "@nestjs/common";
import {
  TWILIO_ACCOUNT_SECRET_AUTH_TOKEN,
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_BASE_URL,
  TWILIO_SERVICE_ID
} from "../common/constants";
import { ServiceError } from "../common/types";

@Injectable()
export class TwilioAuthProvider {
  private readonly logger = new Logger(TwilioAuthProvider.name);

  async sendPasscode(
    mode: string,
    user_contact: string,
  ): Promise<any> {
    try {
      const twilio_auth_token = btoa(
        `${TWILIO_ACCOUNT_SID}:${TWILIO_ACCOUNT_SECRET_AUTH_TOKEN}`,
      );
      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${twilio_auth_token}`,
      };
      const data = {
        To: user_contact,
        Channel: 'sms',
      };
      const twilioResponse = await fetch(
        `${TWILIO_AUTH_BASE_URL}Services/${TWILIO_SERVICE_ID}/Verifications`,
        {
          method: 'POST',
          body: new URLSearchParams(data),
          headers: headers,
        },
      );
      this.logger.log('twilio response ', await twilioResponse.json());
      return twilioResponse;
    } catch (error) {
      this.logger.error('Error sending twilio passcode', error);
      throw new ServiceError('Error sending twilio passcode', error);
    }
  }

  async verifyPasscode(
    user_contact: string,
    code: string,
  ): Promise<boolean> {
    try {
      const twilio_auth_token = btoa(
        `${TWILIO_ACCOUNT_SID}:${TWILIO_ACCOUNT_SECRET_AUTH_TOKEN}`,
      );
      const auth_url = `${TWILIO_AUTH_BASE_URL}Services/${TWILIO_SERVICE_ID}/VerificationCheck`;

      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${twilio_auth_token}`,
      };

      const sms_authenticate = await fetch(auth_url, {
        method: 'POST',
        body: new URLSearchParams({ Code: code, To: user_contact }),
        headers: headers,
      });

      const res = await sms_authenticate.json();
      if (res.status == 'approved') {
        return true;
      }
      return false;
    } catch (error) {
      this.logger.error('Error in validating sms ', error);
      throw new ServiceError(error);
    }
  }
}