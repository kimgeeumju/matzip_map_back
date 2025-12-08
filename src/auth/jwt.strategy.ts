// src/auth/jwt.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    // ✅ env에서 값을 읽고, 없으면 fallback 문자열 사용
    const secret =
      configService.get<string>('JWT_SECRET') ||
      process.env.JWT_SECRET ||
      'your-super-secret-key-123456';

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret, // ← 반드시 string 보장
    });
  }

  // JWT payload에서 유저 정보 꺼내서 request.user에 들어갈 값 리턴
  async validate(payload: any) {
    return {
      userId: payload.sub,
      email: payload.email,
    };
  }
}
