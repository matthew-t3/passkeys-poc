import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { setCookie } from 'hono/cookie';

const app = new Hono();

app.use('*', cors({ credentials: true, origin: 'http://localhost:5173' }));

app.get('/', (c) => {
  return c.text('Hello Hono!');
});

app.get('/challenge', async (c) => {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  setCookie(c, 'challenge', challenge.toString(), {
    sameSite: 'None',
    httpOnly: true,
    secure: true,
  });
  return c.json({
    challenge: challenge.toString(),
  });
});

app.post('/verify', async (c) => {
  const body = await c.req.json();
  const { id, rawId, type, response } = body;
  console.log('response', response);

  if (!id) {
    c.status(400);
    return c.json({
      message: 'id is required',
    });
  }

  if (id !== rawId) {
    c.status(400);
    return c.json({
      message: 'id and rawId must be the same',
    });
  }

  if (type !== 'public-key') {
    c.status(400);
    return c.json({
      message: 'type must be public-key',
    });
  }

  console.log(response.clientDataJSON);
  const utf8String = Buffer.from(response.clientDataJSON, 'base64').toString(
    'utf-8',
  );
  console.log('utf8String', utf8String);

  return c.json({
    message: 'ok',
  });
});

const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
