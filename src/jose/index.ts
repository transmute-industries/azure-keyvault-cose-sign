import { base64url, JWK, ProtectedHeaderParameters, importJWK, compactVerify,  flattenedVerify, FlattenedJWS } from "jose"
import { ClientSecretCredential } from "@azure/identity";
import { KeyClient } from "@azure/keyvault-keys";
import { signWithKey } from "../signWithKey";



const crvToAlg = (crv: string) => {
  switch (crv) {
    case 'P-256': {
      return 'ES256'
    }
  }
  throw new Error('Unsupported curve: ' + crv)
}

export type RequestJosePublicKey = {
  credential: ClientSecretCredential,
  kid: string,
}

export type PublicKey = JWK & { alg: 'ES256' }

export const getPublicKey = async ({ credential, kid }: RequestJosePublicKey) => {
  const [vaultUrl, keyPath] = kid.split('/keys/')
  const client = new KeyClient(vaultUrl, credential);
  const [keyName] = keyPath.split('/')
  const latestKey = await client.getKey(keyName);
  const { kty, crv, x, y } = latestKey.key || {}
  const publicKeyJwk = {
    kid,
    kty,
    crv,
    alg: crvToAlg(`${crv}`),
    x: base64url.encode(new Uint8Array(x || Buffer.from(''))),
    y: base64url.encode(new Uint8Array(y || Buffer.from('')))
  }
  return publicKeyJwk as PublicKey
}


export type RequestJoseSigner = {
  credential: ClientSecretCredential,
  kid: string,
  alg: "ES256",
}

export type RequestJoseKidVerifier = {
  credential: ClientSecretCredential,
  kid: string,
}

export type RequestJosePublicKeyVerifier = {
  publicKeyJwk: PublicKey
}

export type RequestJoseVerifier = RequestJoseKidVerifier | RequestJosePublicKeyVerifier

export const attached = {
  verifier: (req: RequestJoseVerifier) => {
    if ((req as RequestJosePublicKeyVerifier).publicKeyJwk) {
      const { publicKeyJwk } = req as RequestJosePublicKeyVerifier
      return {
        verify: async (jws: string) => {
          return compactVerify(jws, await importJWK(publicKeyJwk))
        }
      }
    } else if ((req as RequestJoseKidVerifier)) {
      const { credential, kid } = req as RequestJoseKidVerifier
      return {
        verify: async (jws: string) => {
          const publicKeyJwk = await getPublicKey({ credential, kid })
          return compactVerify(jws, await importJWK(publicKeyJwk))
        }
      }
    }
    throw new Error('JOSE verifier requires public key or kid and credential')
  },
  signer: ({ credential, kid, alg }: RequestJoseSigner) => {
    return {
      sign: async (header: ProtectedHeaderParameters, payload: Uint8Array) => {
        const tbs = base64url.encode(JSON.stringify(header)) + '.' + base64url.encode(payload)
        const tbsBytes = new TextEncoder().encode(tbs)
        const sig = await signWithKey({
          credential,
          kid,
          alg,
          bytes: tbsBytes
        })
        const jws = tbs + '.' + base64url.encode(sig)
        return jws
      }
    }
  }
}

export type DetachedPayloadJws = { protected:string, payload: Uint8Array, signature: string}

export const detached = {
  verifier: (req: RequestJoseVerifier) => {
    if ((req as RequestJosePublicKeyVerifier).publicKeyJwk) {
      const { publicKeyJwk } = req as RequestJosePublicKeyVerifier
      return {
        verify: async (jws: DetachedPayloadJws) => {
          return flattenedVerify(jws, await importJWK(publicKeyJwk))
        }
      }
    } else if ((req as RequestJoseKidVerifier)) {
      const { credential, kid } = req as RequestJoseKidVerifier
      return {
        verify: async (jws: DetachedPayloadJws) => {
          const publicKeyJwk = await getPublicKey({ credential, kid })
          return flattenedVerify(jws, await importJWK(publicKeyJwk))
        }
      }
    }
    throw new Error('JOSE verifier requires public key or kid and credential')
  },
  signer: ({ credential, kid, alg }: RequestJoseSigner) => {
    return {
      sign: async (header: ProtectedHeaderParameters, payload: Uint8Array) => {
        if (header.b64 !== false) {
          throw new Error('detached jws requires b64: false and crit[b64] in header')
        }
        const tbs = base64url.encode(JSON.stringify(header)) + '.'
        const tbsBytes = Buffer.concat([Buffer.from(tbs), Buffer.from(payload)])
        const sig = await signWithKey({
          credential,
          kid,
          alg,
          bytes: tbsBytes
        })
        const jws = tbs + '.' + base64url.encode(sig)
        return jws
      }
    }
  }
}
