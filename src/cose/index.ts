
import * as cose from '@transmute/cose'
import * as jose from 'jose'
import { ClientSecretCredential } from "@azure/identity";
import { toArrayBuffer } from '@transmute/cose/dist/cbor';
import { signWithKey } from '../signWithKey';
import { getPublicKey } from '../jose';


export type RequestCoseRemoteSigner = {
  credential: ClientSecretCredential,
  kid: string,
  alg: "ES256",
}


export const remote = (req: RequestCoseRemoteSigner) => {
  return {
    sign: async (bytes: ArrayBuffer) => {
      const s = await signWithKey({
        ...req,
        bytes: new Uint8Array(bytes)
      })
      return toArrayBuffer(s)
    }
  }
}

export type RequestCoseKidVerifier = {
  credential: ClientSecretCredential,
  kid: string,
}

export type RequestCosePublicKeyVerifier = {
  publicKeyJwk: jose.JWK & { alg: 'ES256' }
}

export type RequestCoseVerifier = RequestCoseKidVerifier | RequestCosePublicKeyVerifier

export const verifier = (req: RequestCoseVerifier) => {
  if ((req as RequestCosePublicKeyVerifier).publicKeyJwk) {
    const { publicKeyJwk } = req as RequestCosePublicKeyVerifier
    return cose.verifier({
      resolver: {
        resolve: async () => {
          return publicKeyJwk
        }
      }
    })
  } else if ((req as RequestCoseKidVerifier)) {
    const { credential, kid } = req as RequestCoseKidVerifier
    return cose.verifier({
      resolver: {
        resolve: async () => {
          const publicKeyJwk = await getPublicKey({ credential, kid })
          return publicKeyJwk
        }
      }
    })
  }
  throw new Error('COSE verifier requires public key or kid and credential')
}




