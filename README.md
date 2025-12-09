
<br>

# Domain

```ts
interface ImageUri {
  id?: number;
  uri: string;
}

interface Marker {
  id: number;
  latitude: number;
  longitude: number;
  color: string;
  score: number;
}

interface Post extends Marker {
  title: string;
  address: string;
  date: Date | string;
  description: string;
  imageUris: ImageUri[];
  isFavorite?: boolean;
}

interface Profile {
  id: number;
  email: string;
  nickname: string | null;
  imageUri: string | null;
  loginType: 'email' | 'kakao' | 'apple';
}
```

# API

## Auth

#### POST /auth/signup

- requestBody

```
{
    email: string
    password: string
}
```

#### POST /auth/signin

- requestBody

```js
{
  email: string;
  password: string;
}
```

- responseBody

```js
{
  accessToken: string;
  refreshToken: string;
}
```

#### GET /auth/refresh

- header

```js
Authorization: `Bearer ${refreshToken}`;
```

- responseBody

```js
{
  accessToken: string;
  refreshToken: string;
}
```

#### GET /auth/me (getProfile)

- responseBody

```ts
type ResponseProfile = Profile;
```

#### PATCH /auth/me (editProfile)

- requestBody

```ts
type RequestProfile = Omit<Profile, 'id' | 'email' | 'loginType'>;
```

- responseBody

```ts
type ResponseProfile = Profile;
```

#### POST /auth/logout

#### POST /auth/oauth/kakao

- requestBody

```js
{
  token: string;
}
```

- responseBody

```js
{
  accessToken: string;
  refreshToken: string;
}
```

#### POST /auth/oauth/apple

- requestBody

```js
{
  identityToken: string;
  appId: string;
  nickname: string | null;
}
```

- responseBody

```js
{
  accessToken: string;
  refreshToken: string;
}
```

<br>

## Marker & Post

#### GET /markers

- responseBody

```ts
Marker[]
```

#### GET /posts/:id

- param

```ts
{
  id: number;
}
```

- requestBody

```ts
// type ResponsePost = Post;

type ResponseSinglePost = ResponsePost & { isFavorite: boolean };
```

#### DELETE /posts/:id

- param

```ts
{
  id: number;
}
```

#### GET /posts

- query

```js
{
  page: number;
}
```

- responseBody

```js
// type ResponsePost = Post;
ResponsePost[];
```

#### POST /posts

- requestBody

```ts
type RequestCreatePost = Omit<Post, 'id'>;
```

#### PATCH /post/:id

- param

```ts
{
  id: number;
}
```

- requestBody

```ts
type RequestUpdatePost = {
  id: number;
  body: Omit<Post, 'id' | 'longitude' | 'latitude' | 'address'> & {
    imageUris: ImageUri[];
  };
};
```

- responseBody

```ts
type ResponseSinglePost = ResponsePost & { isFavorite: boolean };
```

#### GET /posts (getCalendarPosts)

- query

```ts
{
  year: number;
  month: number;
}
```

- responseBody

```ts
// type CalendarPost = {
//   id: number;
//   title: string;
//   address: string;
// };

type ResponseCalendarPost = Record<number, CalendarPost[]>;
```

#### GET /favorites

- query

```ts
{
  page: number;
}
```

#### POST /favorites/:id

- param

```ts
{
  id: number;
}
```

- responseBody

```ts
{
  id: number;
}
```

<br>

## Image

#### POST /images

- requestBody : `FormData`
- responseBody : `string[]`
