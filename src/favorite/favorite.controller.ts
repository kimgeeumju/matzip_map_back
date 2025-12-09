import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { FavoriteService } from './favorite.service';
import { GetUser } from '../@common/decorators/get-user.decorator';
import { User } from 'src/auth/user.entity';

@Controller('favorites')
@UseGuards(AuthGuard())
export class FavoriteController {
  constructor(private favoriteService: FavoriteService) {}

  @Get('/')
  async getFavoritePosts(@Query('page') page: number, @GetUser() user: User) {
    return this.favoriteService.getFavoritePosts(page, user);
  }

  @Post('/:id')
  toggleFavorite(@Param('id', ParseIntPipe) id: number, @GetUser() user: User) {
    return this.favoriteService.toggleFavorite(id, user);
  }
}
