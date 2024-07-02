const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser
let BASE_URL = 'http://localhost:3000'
const errNode = document.getElementById('error')
const successNode = document.getElementById('success')

function request(path, opt = {}) {
  return fetch(`${BASE_URL}${path}`, { ...opt, credentials: 'include' })
}

function setError(err) {
  successNode.classList.add('hidden')
  errNode.classList.remove('hidden')

  const errorText = document.createTextNode(err)

  errNode.appendChild(errorText)
}

function clearMessages() {
  errNode.classList.add('hidden')
  successNode.classList.add('hidden')
  successNode.innerHTML = ''
  errNode.innerHTML = ''
}

function setSuccessNode(message) {
  errNode.classList.add('hidden')
  successNode.classList.remove('hidden')
  successNode.innerHTML = ''

  successNode.innerHTML = `<pre>${JSON.stringify(message, null, 2)}</pre>`
}

async function init() {
  const response = await request('/auth/options', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({})
  })

  if (!response.ok) {
    return
  }

  response.json()
    .then(data => {

      return startAuthentication(data, true)
    })
    .then(attestation => {
      return request('/auth/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(attestation)
      })
    })
    .then(res => {
      return res.json()
    })
    .then(data => {
      setSuccessNode(data)
    })
    .catch(err => {
      console.error('err', err);
      setError(err.message)
    })
}


window.addEventListener('load', function () {
  // your code here
  if (globalThis?.BASE_URL) {
    BASE_URL = globalThis?.BASE_URL
    console.log('BASE_URL', BASE_URL);
  }
  init()
})

async function onSubmit(evt) {
  clearMessages()
  evt.preventDefault()

  const formEl = document.getElementById('registration')

  const formData = new FormData(formEl)

  const username = formData.get('username')

  let response

  try {
    response = await request('/register/options', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username })
    })
  } catch (err) {
    console.error('err', err);
    setError(err.message)
  }

  if (!response.ok) {
    const { message } = await response.json()
    return setError(message)
  }

  const opts = await response.json()
  let attestationResponse

  try {
    attestationResponse = await startRegistration(opts)
    console.log('attestationResponse', attestationResponse);
  } catch (err) {
    console.error('err', err);
    setError(err.message)
  }

  await request('/register/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(attestationResponse)
  })
}

async function onAuthenticate(evt) {
  clearMessages()
  evt.preventDefault()
  console.log('called')

  const formEl = document.getElementById('authenticate')

  const formData = new FormData(formEl)

  const username = formData.get('username')

  let response

  try {
    response = await request('/auth/options', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username })
    })
  } catch (err) {
    console.error('err', err);
    setError(err.message)
  }


  if (!response.ok) {
    const { message } = await response.json()
    return setError(message)
  }

  const opts = await response.json()
  let attestationResponse

  try {
    attestationResponse = await startAuthentication(opts)
    console.log('attestationResponse', attestationResponse);
  } catch (err) {
    console.error('err', err);
    setError(err.message)
  }

  const verificationResponse = await request('/auth/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(attestationResponse)
  })

  const message = await verificationResponse.json()
  setSuccessNode(message)
}