const BASE_URL = 'http://localhost:3000'

function request(path, opt = {}) {
  return fetch(`${BASE_URL}${path}`, { ...opt, credentials: 'include' })
}

let challenge = new Uint8Array(32)

async function getChallenge() {
  const res = await request('/challenge')

  const { challenge: challengeStr } = await res.json();

  return challengeStr
}

async function init() {
  if (!navigator.credentials) {
    const errNode = document.getElementById('error')

    errNode.classList.remove('hidden')

    const errorText = document.createTextNode('WebAuthn is not available on your browser')

    errNode.appendChild(errorText)
  }

  const challengeRes = await getChallenge()

  challenge = Uint8Array.from(challengeRes.split(','))
}

init()

/**
 * 
 * @param {ArrayBuffer} buffer 
 */
function bufferToBase64URLString(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * 
 * @param {Credential} credential 
 */
function credToJSON(credential) {
  const { id, rawId, response, type } = credential

  const transports = response.getTransports()
  const responsePublicKeyAlgorithm = response.getPublicKeyAlgorithm()

  const responsePublicKey = response.getPublicKey()
  const publicKey = bufferToBase64URLString(responsePublicKey)
  const authenticatorData = bufferToBase64URLString(response.getAuthenticatorData())

  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      attestationObject: bufferToBase64URLString(response.attestationObject),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      transports,
      publicKeyAlgorithm: responsePublicKeyAlgorithm,
      publicKey,
      authenticatorData,
    },
    type,
  }
}

async function onSubmit(evt) {
  evt.preventDefault()

  const formEl = document.getElementById('registration')

  const formData = new FormData(formEl)

  const username = formData.get('username')

  const opt = {
    publicKey: {
      challenge,
      rp: {
        name: 'My Secure Application',
        id: 'localhost'
      },
      user: {
        id: crypto.getRandomValues(new Uint8Array(32)),
        displayName: username,
        name: username,
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" }
      ],
      attestation: 'direct',
    }
  }

  const creds = await navigator.credentials.create(opt)
  console.log('creds', creds);

  const jsonData = credToJSON(creds)

  await request('/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(jsonData)
  })
}

async function authenticate() {
  console.log('called')

  const challengeRes = await getChallenge()
  console.log('challengeRes', challengeRes.toString());
}