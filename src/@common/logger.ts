import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private logger = new Logger('HTTP');

  use(request: Request, response: Response, next: NextFunction): void {
    const { method, originalUrl } = request;
    const userAgent = request.get('user-agent') || '';

    // 이미지 확장자 로그 제외
    const isImageRequest = /\.(jpg|jpeg|png|webp|gif|svg)$/i.test(originalUrl);

    response.on('finish', () => {
      const { statusCode } = response;

      if (!isImageRequest) {
        this.logger.log(
          `[${method}] ${originalUrl} (${statusCode}) (${userAgent})`,
        );
      }
    });

    next();
  }
}
