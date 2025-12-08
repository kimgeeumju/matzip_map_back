import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { CreatePostDto } from './dto/create-post.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Post } from './post.entity';
import { Brackets, Repository, SelectQueryBuilder } from 'typeorm';
import { User } from 'src/auth/user.entity';
import { Image } from 'src/image/image.entity';
import { sleep } from 'src/@common/sleep';

@Injectable()
export class PostService {
  constructor(
    @InjectRepository(Post)
    private postRepository: Repository<Post>,
    @InjectRepository(Image)
    private imageRepository: Repository<Image>,
  ) {}

  async getAllMarkers(user: User) {
    try {
      const markers = await this.postRepository
        .createQueryBuilder('post')
        .where('post.userId = :userId', { userId: user.id })
        .select([
          'post.id',
          'post.latitude',
          'post.longitude',
          'post.color',
          'post.score',
        ])
        .getMany();

      return markers;
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException(
        '마커를 가져오는 도중 에러가 발생했습니다.',
      );
    }
  }

  private getPostsWithOrderImages(posts: Post[]) {
    return posts.map((post) => {
      const { images, ...rest } = post;
      const newImages = [...images].sort((a, b) => a.id - b.id);
      return { ...rest, imageUris: newImages };
    });
  }

  private async getPostsBaseQuery(
    userId: number,
  ): Promise<SelectQueryBuilder<Post>> {
    return this.postRepository
      .createQueryBuilder('post')
      .leftJoinAndSelect('post.images', 'image')
      .where('post.userId = :userId', { userId })
      .orderBy('post.date', 'DESC');
  }

  async getMyPosts(page: number, user: User) {
    const perPage = 10;
    const offset = (page - 1) * perPage;
    const queryBuilder = await this.getPostsBaseQuery(user.id);
    const posts = await queryBuilder.take(perPage).skip(offset).getMany();

    // await sleep(3000);
    return this.getPostsWithOrderImages(posts);
  }

  async getPostById(id: number, user: User) {
    try {
      const foundPost = await this.postRepository
        .createQueryBuilder('post')
        .leftJoinAndSelect('post.images', 'image')
        .leftJoinAndSelect(
          'post.favorites',
          'favorite',
          'favorite.userId = :userId',
          { userId: user.id },
        )
        .where('post.userId = :userId', { userId: user.id })
        .andWhere('post.id = :id', { id })
        .getOne();

      if (!foundPost) {
        throw new NotFoundException('존재하지 않는 피드입니다.');
      }

      const { favorites, images, ...rest } = foundPost;
      const postWithIsFavorites = {
        ...rest,
        isFavorite: favorites.length > 0,
        imageUris: images,
      };

      return postWithIsFavorites;
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException(
        '장소를 가져오는 도중 에러가 발생했습니다.',
      );
    }
  }

  async createPost(createPostDto: CreatePostDto, user: User) {
    try {
      const {
        latitude,
        longitude,
        color,
        address,
        title,
        description,
        date,
        score,
        imageUris,
      } = createPostDto;
      const post = this.postRepository.create({
        latitude,
        longitude,
        color,
        address,
        title,
        description,
        date,
        score,
        user,
      });
      const images = imageUris.map((uri) => this.imageRepository.create(uri));
      post.images = images;

      await this.imageRepository.save(images);
      await this.postRepository.save(post);

      const { user: _, ...postWithoutUser } = post;
      return postWithoutUser;
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException(
        '장소를 추가하는 도중 에러가 발생했습니다.',
      );
    }
  }

  async deletePost(id: number, user: User) {
    try {
      const result = await this.postRepository
        .createQueryBuilder('post')
        .delete()
        .from(Post)
        .where('userId = :userId', { userId: user.id })
        .andWhere('id = :id', { id })
        .execute();

      if (result.affected === 0) {
        throw new NotFoundException('존재하지 않는 피드입니다.');
      }

      return id;
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException(
        '장소를 삭제하는 도중 에러가 발생했습니다.',
      );
    }
  }

  async updatePost(
    id: number,
    updatePostDto: Omit<CreatePostDto, 'latitude' | 'longitude' | 'address'>,
    user: User,
  ) {
    const postEntity = await this.postRepository.findOne({
      where: { id, user: { id: user.id } },
      relations: ['images'],
    });

    if (!postEntity) {
      throw new NotFoundException('존재하지 않는 피드입니다.');
    }

    const { title, description, color, date, score, imageUris } = updatePostDto;

    if (postEntity.images?.length) {
      const imageIds = postEntity.images.map((img) => img.id);
      await this.imageRepository.delete(imageIds);
    }

    const newImages = imageUris.map((uri) => this.imageRepository.create(uri));
    await this.imageRepository.save(newImages);

    postEntity.title = title;
    postEntity.description = description;
    postEntity.color = color;
    postEntity.date = date;
    postEntity.score = score;
    postEntity.images = newImages;

    try {
      await this.postRepository.save(postEntity);
      const { images, ...rest } = postEntity;
      return { ...rest, imageUris: newImages };
    } catch (error) {
      console.log(error);
      throw new InternalServerErrorException(
        '장소를 수정하는 도중 에러가 발생했습니다.',
      );
    }
  }

  async getPostsByMonth(year: number, month: number, user: User) {
    const posts = await this.postRepository
      .createQueryBuilder('post')
      .where('post.userId = :userId', { userId: user.id })
      .andWhere('extract(year from post.date) = :year', { year })
      .andWhere('extract(month from post.date) = :month', { month })
      .select([
        'post.id AS id',
        'post.title AS title',
        'post.address AS address',
        'EXTRACT(DAY FROM post.date) AS date',
      ])
      .getRawMany();

    const groupPostsByDate = posts.reduce((acc, post) => {
      const { id, title, address, date } = post;

      if (!acc[date]) {
        acc[date] = [];
      }
      acc[date].push({ id, title, address });

      return acc;
    }, {});

    return groupPostsByDate;
  }
}
