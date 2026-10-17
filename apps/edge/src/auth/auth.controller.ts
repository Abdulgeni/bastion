import { BadRequestException, Body, Controller, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

interface LoginBody {
  readonly username?: unknown;
  readonly password?: unknown;
}

/** POST /login — no cert, no JWT: this is where a user gets their token. */
@Controller('login')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post()
  async login(@Body() body: LoginBody): Promise<{ token: string }> {
    if (typeof body.username !== 'string' || typeof body.password !== 'string') {
      throw new BadRequestException();
    }
    const token = await this.auth.login(body.username, body.password);
    if (token === undefined) throw new UnauthorizedException();
    return { token };
  }
}
