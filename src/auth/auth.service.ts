// src/auth/auth.service.ts
import axios from 'axios';
import appleSignin from 'apple-signin-auth';
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { EditProfileDto } from './dto/edit-profile.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  // 🔐 회원가입 (이메일 로그인 전용) - DB에 유저 저장만
  async signup(authDto: AuthDto) {
    // 이메일은 소문자 + 공백 제거해서 통일
    const email = authDto.email.trim().toLowerCase();
    const password = authDto.password;

    // 0) 이미 같은 이메일의 email 로그인 계정 있는지 확인
    const exists = await this.userRepository.findOne({
      where: { email, loginType: 'email' },
    });

    if (exists) {
      throw new ConflictException('이미 존재하는 이메일입니다.');
    }

    // 1) 비밀번호 해시
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    // 2) 유저 엔티티 생성
    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      loginType: 'email',
    });

    // 3) 저장만 하고 끝 (토큰 발급 X)
    try {
      await this.userRepository.save(user);
      return;
    } catch (error: any) {
      console.log('SIGNUP SAVE ERROR:', error);

      if (error && error.code === '23505') {
        throw new ConflictException('이미 존재하는 이메일입니다.');
      }

      throw new InternalServerErrorException(
        '회원가입 도중 에러가 발생했습니다.',
      );
    }
  }

  // 🔑 토큰 발급 유틸 (환경변수 없어도 기본값으로 동작)
  private async getTokens(payload: { email: string }) {
    const secret =
      this.configService.get<string>('JWT_SECRET') ?? 'dev-secret-key';

    const accessExp =
      this.configService.get<string>('JWT_ACCESS_TOKEN_EXPIRATION') ?? '1h';

    const refreshExp =
      this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRATION') ?? '7d';

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret,
        expiresIn: accessExp,
      }),
      this.jwtService.signAsync(payload, {
        secret,
        expiresIn: refreshExp,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  // 🔐 이메일 로그인
  async signin(authDto: AuthDto) {
    // signup과 동일하게 정규화
    const email = authDto.email.trim().toLowerCase();
    const password = authDto.password;

    // 1) 이메일 + loginType으로 유저 찾기
    const user = await this.userRepository.findOne({
      where: { email, loginType: 'email' },
    });

    console.log('SIGNIN TRY:', email);
    console.log(
      'FOUND USER:',
      user && { id: user.id, email: user.email, loginType: user.loginType },
    );

    if (!user) {
      console.log('SIGNIN FAIL: user not found');
      throw new UnauthorizedException(
        '이메일 또는 비밀번호가 일치하지 않습니다.',
      );
    }

    // 2) 비밀번호 비교
    const isMatch = await bcrypt.compare(password, user.password);
    console.log('PASSWORD MATCH:', isMatch);

    if (!isMatch) {
      throw new UnauthorizedException(
        '이메일 또는 비밀번호가 일치하지 않습니다.',
      );
    }

    // 3) 토큰 발급 + refresh 토큰 해시 저장
    const { accessToken, refreshToken } = await this.getTokens({ email });

    try {
      await this.updateHashedRefreshToken(user.id, refreshToken);
    } catch (error) {
      console.log('UPDATE REFRESH TOKEN ERROR:', error);
      // 토큰 저장 실패해도, 일단 로그인은 되게 토큰은 반환
      return { accessToken, refreshToken };
    }

    return { accessToken, refreshToken };
  }

  private async updateHashedRefreshToken(id: number, refreshToken: string) {
    const salt = await bcrypt.genSalt();
    const hashedRefreshToken = await bcrypt.hash(refreshToken, salt);

    await this.userRepository.update(id, { hashedRefreshToken });
  }

  async refreshToken(user: User) {
    const { email } = user;

    if (!user.hashedRefreshToken) {
      throw new ForbiddenException();
    }

    const { accessToken, refreshToken } = await this.getTokens({ email });
    await this.updateHashedRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken };
  }

  getProfile(user: User) {
    const { password, hashedRefreshToken, ...rest } = user;
    return { ...rest };
  }

  async editProfile(editProfileDto: EditProfileDto, user: User) {
    const profile = await this.userRepository
      .createQueryBuilder('user')
      .where('user.id = :userId', { userId: user.id })
      .getOne();

    if (!profile) {
      throw new NotFoundException('존재하지 않는 사용자입니다.');
    }

    const { nickname, imageUri } = editProfileDto;
    profile.nickname = nickname;
    profile.imageUri = imageUri;

    try {
      await this.userRepository.save(profile);
      const { password, hashedRefreshToken, ...rest } = profile;
      return { ...rest };
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException(
        '프로필 수정 도중 에러가 발생했습니다.',
      );
    }
  }

  async deleteRefreshToken(user: User) {
    try {
      await this.userRepository.update(user.id, { hashedRefreshToken: null });
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException();
    }
  }

  // 🔐 카카오 로그인
  async kakaoLogin(kakaoToken: { token: string }) {
    const url = 'https://kapi.kakao.com/v2/user/me';
    const headers = {
      Authorization: `Bearer ${kakaoToken.token}`,
      'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
    };

    try {
      const response = await axios.get(url, { headers });
      const userData = response.data;
      const { id: kakaoId, kakao_account } = userData;
      const nickname = kakao_account?.profile.nickname;

      const existingUser = await this.userRepository.findOne({
        where: { email: kakaoId.toString(), loginType: 'kakao' },
      });

      if (existingUser) {
        const { accessToken, refreshToken } = await this.getTokens({
          email: existingUser.email,
        });

        await this.updateHashedRefreshToken(existingUser.id, refreshToken);
        return { accessToken, refreshToken };
      }

      const newUser = this.userRepository.create({
        email: kakaoId.toString(),
        password: nickname ?? '',
        nickname,
        loginType: 'kakao',
      });

      try {
        await this.userRepository.save(newUser);
      } catch (error) {
        console.log(error);
        throw new InternalServerErrorException();
      }

      const { accessToken, refreshToken } = await this.getTokens({
        email: newUser.email,
      });

      await this.updateHashedRefreshToken(newUser.id, refreshToken);
      return { accessToken, refreshToken };
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException('Kakao 서버 에러가 발생했습니다.');
    }
  }

  // 🔐 애플 로그인
  async appleLogin(appleIdentity: {
    identityToken: string;
    appId: string;
    nickname: string | null;
  }) {
    const { identityToken, appId, nickname } = appleIdentity;

    try {
      const { sub: userAppleId } = await appleSignin.verifyIdToken(
        identityToken,
        {
          audience: appId,
          ignoreExpiration: true,
        },
      );

      const existingUser = await this.userRepository.findOne({
        where: { email: userAppleId, loginType: 'apple' },
      });

      if (existingUser) {
        const { accessToken, refreshToken } = await this.getTokens({
          email: existingUser.email,
        });

        await this.updateHashedRefreshToken(existingUser.id, refreshToken);
        return { accessToken, refreshToken };
      }

      const newUser = this.userRepository.create({
        email: userAppleId,
        nickname: nickname === null ? '이름없음' : nickname,
        password: '',
        loginType: 'apple',
      });

      try {
        await this.userRepository.save(newUser);
      } catch (error) {
        console.log(error);
        throw new InternalServerErrorException();
      }

      const { accessToken, refreshToken } = await this.getTokens({
        email: newUser.email,
      });

      await this.updateHashedRefreshToken(newUser.id, refreshToken);
      return { accessToken, refreshToken };
    } catch (error) {
      console.log('error', error);
      throw new InternalServerErrorException(
        'Apple 로그인 도중 문제가 발생했습니다.',
      );
    }
  }
}
