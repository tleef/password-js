/* eslint-env mocha */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import chaiAsPromised from 'chai-as-promised'

import crypto from 'crypto'

import pwd from './password'

const expect = chai.expect

chai.use(sinonChai)
chai.use(chaiAsPromised)

describe('password', () => {
  describe('#hash()', () => {
    it('should successfully hash a password', async () => {
      const hash = await pwd.hash('SuperSecretPassword')

      expect(hash).to.be.a('string')
    })

    it('should throw if password is not a string', async () => {
      await expect(pwd.hash(123)).to.be.rejectedWith('password must be a non-empty String')
    })

    it('should throw if password is an empty string', async () => {
      await expect(pwd.hash('')).to.be.rejectedWith('password must be a non-empty String')
    })

    describe('pbkdf2', () => {
      beforeEach(() => { sinon.stub(crypto, 'pbkdf2') })
      afterEach(() => { crypto.pbkdf2.restore() })

      it('should throw if crypto.pbkdf2() returns an error', () => {
        crypto.pbkdf2.callsArgWith(5, new Error('some error'))

        expect(pwd.hash('SuperSecretPassword')).to.be.rejectedWith('error hashing password with pbkdf2')
      })
    })

    describe('randomBytes', () => {
      beforeEach(() => { sinon.stub(crypto, 'randomBytes') })
      afterEach(() => { crypto.randomBytes.restore() })

      it('should throw if crypto.randomBytes() returns an error', () => {
        crypto.randomBytes.callsArgWith(1, new Error('some error'))

        expect(pwd.hash('SuperSecretPassword')).to.be.rejectedWith('error generating salt')
      })
    })
  })

  describe('#verify()', () => {
    it('should successfully verify a password', async () => {
      const res = await pwd.verify('SuperSecretPassword', await pwd.hash('SuperSecretPassword'))

      expect(res).to.equal(true)
    })

    it('should not verify incorrectly password', async () => {
      const res = await pwd.verify('SuperSecretPassword', await pwd.hash('superSecretPassword'))

      expect(res).to.equal(false)
    })

    it('should throw if password is not a string', async () => {
      await expect(pwd.verify(123, 'test')).to.be.rejectedWith('password must be a non-empty String')
    })

    it('should throw if password is an empty string', async () => {
      await expect(pwd.verify('', 'test')).to.be.rejectedWith('password must be a non-empty String')
    })

    it('should throw if hash is not a string', async () => {
      await expect(pwd.verify('test', 123)).to.be.rejectedWith('hash must be a non-empty String')
    })

    it('should throw if hash is an empty string', async () => {
      await expect(pwd.verify('test', '')).to.be.rejectedWith('hash must be a non-empty String')
    })

    it('should throw if hash is wrong length', async () => {
      await expect(pwd.verify('test', 'one$two$three')).to.be.rejectedWith('hash not formatted correctly')
    })

    it('should throw if hash is missing data', async () => {
      await expect(pwd.verify('test', '$two$three$four')).to.be.rejectedWith('hash not formatted correctly')
      await expect(pwd.verify('test', 'one$$three$four')).to.be.rejectedWith('hash not formatted correctly')
      await expect(pwd.verify('test', 'one$two$$four')).to.be.rejectedWith('hash not formatted correctly')
      await expect(pwd.verify('test', 'one$two$three$')).to.be.rejectedWith('hash not formatted correctly')
    })

    it('should throw if hash uses wrong algorithm', async () => {
      await expect(pwd.verify('test', 'one$two$three$four')).to.be.rejectedWith('hash uses wrong algorithm')
    })

    it('should throw if hash uses wrong number of iterations', async () => {
      await expect(pwd.verify('test', 'pbkdf2$two$three$four')).to.be.rejectedWith('hash uses wrong number of iterations')
    })
  })
})
