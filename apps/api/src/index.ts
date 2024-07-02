import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { setCookie, getCookie } from 'hono/cookie';
import {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { generateIdFromEntropySize } from 'lucia';

const app = new Hono();

const rpName = 'Sample Passkey application';
// const rpID = 'localhost';
const rpID = 'my-one-billion-project.vercel.app';
const origin = `https://${rpID}`;
const cookieOpts = {
  sameSite: 'None',
  httpOnly: true,
  secure: true,
} as const;

type User = {
  id: string;
  username: string;
};

type Passkey = {
  user: User;
  counter: number;
  credentialPublicKey: Uint8Array;
  credentialID: string;
  aaguid: string;
  transports: AuthenticatorTransport[];
};

// key is user.username
const users = new Map<string, User>();
// key is user.id
const passkeys = new Map<string, Array<Passkey>>();

app.use(
  '*',
  cors({
    credentials: true,
    origin: [
      'http://localhost:5173',
      'https://evil-website-liart.vercel.app',
      'https://my-one-billion-project.vercel.app',
    ],
  }),
);

app.get('/', (c) => {
  return c.text('ok!');
});

app.post('/register/options', async (c) => {
  const { username } = await c.req.json<{ username: string }>();

  let userInfo = users.get(username);
  if (!userInfo) {
    userInfo = { id: generateIdFromEntropySize(10), username };
  }

  users.set(username, userInfo);
  const credentials = passkeys.get(userInfo.id);

  const opts: GenerateRegistrationOptionsOpts = {
    rpName,
    rpID,
    userName: username,
    attestationType: 'none',
    excludeCredentials: (credentials ?? []).map((cred) => ({
      id: cred.credentialID,
      type: 'public-key',
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
      userVerification: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  setCookie(c, 'challenge', options.challenge, cookieOpts);
  setCookie(c, 'username', username, cookieOpts);

  return c.json(options);
});

app.post('register/verify', async (c) => {
  const body = await c.req.json();
  const username = getCookie(c, 'username') as string;
  const expectedChallenge = getCookie(c, 'challenge') as string;

  let verification: VerifiedRegistrationResponse;
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (e) {
    console.error(e);
    let message = 'Something went wrong';

    if (e instanceof Error) {
      message = e.message;
    }

    return c.json(
      {
        message,
      },
      400,
    );
  }

  const { verified, registrationInfo } = verification;
  console.log('verified', verified);
  console.log('registrationInfo', registrationInfo);

  const user = users.get(username);
  console.log('user', user);

  if (verified && registrationInfo) {
    if (!user) {
      return c.json({ message: 'User does not exist' }, 400);
    }

    console.log('body.response.transports', body.response.transports);
    const passKey: Passkey = {
      user,
      counter: registrationInfo.counter,
      credentialPublicKey: registrationInfo.credentialPublicKey,
      credentialID: registrationInfo.credentialID,
      aaguid: registrationInfo.aaguid,
      transports: body.response.transports,
    };

    const credentials = passkeys.get(user.id) ?? [];
    credentials.push(passKey);
    passkeys.set(user.id, credentials);
  }

  setCookie(c, 'challenge', '', cookieOpts);

  return c.json({ verified }, 200);
});

app.post('/auth/options', async (c) => {
  let username = getCookie(c, 'username') as string;
  const body = await c.req.json<{ username: string }>();

  if (body.username) {
    username = body.username;
  }

  if (!username) {
    return c.json({ message: 'Not authenticated' }, 400);
  }

  const user = users.get(username);
  let credentials = passkeys.get(user?.id ?? '');
  if (!user || !credentials) {
    return c.json({ message: 'User does not exist' }, 400);
  }

  const opts: GenerateAuthenticationOptionsOpts = {
    allowCredentials: credentials.map((cred) => ({
      id: cred.credentialID,
      type: 'public-key',
      transports: cred.transports,
    })),
    userVerification: 'preferred',
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  setCookie(c, 'challenge', options.challenge, cookieOpts);
  setCookie(c, 'username', username, cookieOpts);

  return c.json(options);
});

app.post('/auth/verify', async (c) => {
  const body = await c.req.json();

  const username = getCookie(c, 'username') as string;
  const expectedChallenge = getCookie(c, 'challenge') as string;
  const user = users.get(username);

  let credentials = passkeys.get(user?.id ?? '');
  if (!user || !credentials) {
    return c.json({ message: 'Not authenticated' }, 400);
  }

  const authenticator = credentials.find(
    (cred) => cred.credentialID === body.id,
  );

  if (!authenticator) {
    return c.json({ message: 'Authenticator not found' }, 400);
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
      requireUserVerification: false,
    };

    verification = await verifyAuthenticationResponse(opts);
  } catch (e) {
    console.error(e);
    let message = 'Something went wrong';

    if (e instanceof Error) {
      message = e.message;
    }

    return c.json(
      {
        message,
      },
      400,
    );
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    authenticator.counter = authenticationInfo.newCounter;
  }

  setCookie(c, 'challenge', '', cookieOpts);

  return c.json({ verified, authenticationInfo, user }, 200);
});

const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
