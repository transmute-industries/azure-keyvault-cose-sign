// eslint-disable-next-line @typescript-eslint/no-var-requires
require('dotenv').config();

import { ClientSecretCredential } from "@azure/identity";

import * as api from '../src'
import * as cose from '@transmute/cose'

const tenantId = `${process.env.AZURE_TENANT_ID}`
const clientId = `${process.env.AZURE_CLIENT_ID}`
const clientSecret = `${process.env.AZURE_CLIENT_SECRET}`
const kid = `${process.env.AZURE_KEY_ID}`
const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
const message = 'It’s a dangerous business, Frodo, going out your door.'
const payload = new TextEncoder().encode(message)

it('get azure key vault public key', async () => {
  const publicKeyJwk2 = await api.jose.getPublicKey({ credential, kid })
  expect(publicKeyJwk2.crv).toEqual('P-256')
  expect(publicKeyJwk2.alg).toEqual('ES256')
})

it('attached jws', async () => {
  const header = { kid, alg: 'ES256', }
  const jws = await api.jose.attached
    .signer({ credential, kid, alg: 'ES256' })
    .sign(header, payload)
  const verified = await api.jose.attached
    .verifier({ credential, kid })
    .verify(jws)
  expect(new TextDecoder().decode(verified.payload)).toBe(message)
})

it('detached jws', async () => {
  const header = { kid, alg: 'ES256', b64: false, crit: ['b64'] }
  const jws = await api.jose.detached
    .signer({ credential, kid, alg: 'ES256' })
    .sign(header, payload)
  const [protectedHeader, signature] = jws.split('..')
  const verified = await api.jose.detached.verifier({ credential, kid }).verify({ protected: protectedHeader, payload, signature })
  expect(new TextDecoder().decode(verified.payload)).toBe(message)
})

it('cose sign1', async () => {
  const coseSign1 = await cose
    .signer({
      remote: await api.cose.remote({ credential, kid, alg: 'ES256' })
    })
    .sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.Protected.Alg, cose.Signature.ES256],
      ]),
      payload,
    })
  const verified = await api.cose
    .verifier({ credential, kid })
    .verify({
      coseSign1
    })
  expect(new TextDecoder().decode(verified)).toBe(message)
})

it('cose hash envelope', async () => {
  const coseSign1 = await cose.hash
    .signer({
      remote: await api.cose.remote({ credential, kid, alg: 'ES256' })
    })
    .sign({
      protectedHeader: cose.ProtectedHeader([
        [cose.Protected.Alg, cose.Signature.ES256],
        [cose.Protected.PayloadHashAlgorithm, cose.Hash.SHA256],
        [cose.Protected.PayloadPreImageContentType, "application/spdx+json"],
        [cose.Protected.PayloadLocation, "https://<ACCOUNT>.blob.core.windows.net/<PATH>/<FILENAME>"],
      ]),
      payload,
    })
  const publicKeyJwk = await api.jose.getPublicKey({credential, kid})
  const verified = await api.cose
    .verifier({ publicKeyJwk })
    .verify({
      coseSign1
    })
  expect(Buffer.from(verified).toString('hex')).toBe("ed5fd4988b349c02e8a05926ff26ab09e6ab0a7ab7c22b785e8c7320f080885f")
})





