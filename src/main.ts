import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';

dotenv.config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: 'http://localhost:3001', // Frontend URL
    methods: 'GET,POST,PUT,DELETE',
  });
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
