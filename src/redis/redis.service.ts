import { Injectable } from '@nestjs/common';
import * as redisClient from 'ioredis';
import Redis from 'ioredis';

@Injectable()
export class RedisService {
  private client: redisClient.Redis;

  constructor() {
    this.client = new Redis({
      host: 'localhost',
      port: 6379,
      // add other options if needed
    });
  }

  async blacklistToken(jti: string, expiresIn: number): Promise<void> {
    await this.client.set(`blacklist:${jti}`, 'true', 'EX', expiresIn);
  }

  async isTokenBlacklisted(jti: string): Promise<boolean> {
    const isBlacklisted = await this.client.get(`blacklist:${jti}`);
    return isBlacklisted !== null;
  }
}
