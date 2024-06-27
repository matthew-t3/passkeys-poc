import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { setCookie, getCookie } from 'hono/cookie';
import { generateIdFromEntropySize } from 'lucia';
import { decode } from 'cbor-x';

const app = new Hono();

const issuedChallenges: Set<string> = new Set();

app.use('*', cors({ credentials: true, origin: 'http://localhost:5173' }));

app.get('/', (c) => {
  return c.text('Hello Hono!');
});

app.get('/challenge', async (c) => {
  const challenge = generateIdFromEntropySize(32);

  issuedChallenges.add(challenge);

  setCookie(c, 'challenge', challenge, {
    sameSite: 'None',
    httpOnly: true,
    secure: true,
  });

  return c.json({
    challenge,
  });
});

app.post('/verify', async (c) => {
  const body = await c.req.json();
  const { id, rawId, type, response } = body;
  const challengeCookie = getCookie(c, 'challenge');

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

  if (!issuedChallenges.has(challengeCookie ?? '')) {
    c.status(400);
    return c.json({
      message: 'invalid challenge',
    });
  }

  const utf8String = Buffer.from(response.clientDataJSON, 'base64').toString(
    'utf-8',
  );
  const { type: authType, origin, challenge } = JSON.parse(utf8String);

  if (authType !== 'webauthn.create') {
    c.status(400);
    return c.json({
      message: 'type must be webauthn.create',
    });
  }

  if (origin !== 'http://localhost:5173') {
    c.status(400);
    return c.json({
      message: 'invalid origin',
    });
  }

  const utf8Challenge = Buffer.from(challenge, 'base64').toString('utf-8');

  if (utf8Challenge !== challengeCookie) {
    c.status(400);
    return c.json({
      message: 'invalid challenge',
    });
  }

  console.log('attestationobject', response.attestationObject);
  const attestationObject = decode(
    Buffer.from(response.attestationObject, 'base64url'),
  );
  console.log('attestationObject', attestationObject);
  const fmt = attestationObject.fmt;
  console.log('fmt', fmt);
  const authData = attestationObject.authData;
  console.log('authData', authData);
  const attStmt = attestationObject.attStmt;
  console.log('attStmt', attStmt);

  const dataView = new DataView(new ArrayBuffer(2));
  const idLenBytes = authData.slice(53, 55);
  console.log('idLenBytes', idLenBytes);
  idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
  console.log('dataView', dataView);
  const credentialIdLength = dataView.getUint16(0);
  console.log('credentialIdLength', credentialIdLength);

  const credentialId = authData.slice(55, 55 + credentialIdLength);
  console.log('credentialId', credentialId.toString('hex'));

  const publicKeyBytes = authData.slice(55 + credentialIdLength);
  console.log('publicKeyBytes', publicKeyBytes);

  // // the publicKeyBytes are encoded again as CBOR
  const publicKeyObject = decode(publicKeyBytes);
  console.log(publicKeyObject);

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
