import crypto from 'crypto'

import type from '@tleef/type-js'

const saltLen = 64

const params = {
  pbkdf2: {
    iterations: 100000,
    keyLen: 256,
    digest: 'sha512'
  }
}

const hash = async (password, salt) => {
  if (!password || !type.isString(password)) {
    throw new Error('password must be a non-empty String')
  }

  if (!salt) {
    try {
      salt = await randomBytes(saltLen)
    } catch (e) {
      throw new Error('error generating salt')
    }
  }

  if (type.isString(salt)) {
    salt = Buffer.from(salt, 'hex')
  }

  let key

  try {
    key = await pbkdf2(password, salt, params.pbkdf2.iterations, params.pbkdf2.keyLen, params.pbkdf2.digest)
  } catch (e) {
    throw new Error('error hashing password with pbkdf2')
  }

  return `pbkdf2$${params.pbkdf2.iterations}$${salt.toString('hex')}$${key.toString('hex')}`
}

const verify = async (password, checkHash) => {
  if (!password || !type.isString(password)) {
    throw new Error('password must be a non-empty String')
  }

  if (!checkHash || !type.isString(checkHash)) {
    throw new Error('hash must be a non-empty String')
  }

  const key = checkHash.split('$')

  if (key.length !== 4 || !key[0] || !key[1] || !key[2] || !key[3]) {
    throw new Error('hash not formatted correctly')
  }

  if (key[0] !== 'pbkdf2') {
    throw new Error('hash uses wrong algorithm')
  }

  if (key[1] !== params.pbkdf2.iterations.toString()) {
    throw new Error('hash uses wrong number of iterations')
  }

  const hashedPassword = await hash(password, key[2])

  return hashedPassword === checkHash
}

function pbkdf2 (password, salt, iterations, keyLen, digest) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keyLen, digest, (err, derivedKey) => {
      if (err) {
        reject(err)
        return
      }

      resolve(derivedKey)
    })
  })
}

function randomBytes (size) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(size, (err, buf) => {
      if (err) {
        reject(err)
        return
      }

      resolve(buf)
    })
  })
}

export default {
  hash,
  verify
}
