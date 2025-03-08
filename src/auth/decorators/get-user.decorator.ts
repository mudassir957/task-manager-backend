import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from 'src/users/user.entity';

export const GetUser = createParamDecorator(
  (data: keyof User | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return data ? request.user?.[data] : request.user;
  },
);
