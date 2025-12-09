import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    const secret =
      configService.get<string>('JWT_SECRET') ||
      process.env.JWT_SECRET ||
      'your-super-secret-key-123456';

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret, 
    });
  }
  async validate(payload: any) {
    return {
      userId: payload.sub,
      email: payload.email,
    };
  }
}
