import { Body, Controller, Post } from '@nestjs/common';
import { MailService } from './mail.service';

@Controller('mail')
export class MailController {
  constructor(private readonly mailService: MailService) {}

  @Post('send')
  async sendTestEmail(@Body('email') email: string) {
    const subject = 'Test Email';
    const html = '<p>This is a test email</p>';
    return this.mailService.sendEmail(email, subject, html);
  }
}
