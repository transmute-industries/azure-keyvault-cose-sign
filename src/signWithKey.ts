
import { ClientSecretCredential } from "@azure/identity";
import { KeyClient, CryptographyClient } from "@azure/keyvault-keys";
import { createHash } from "crypto";

export type RequestSignWithKey = {
  credential: ClientSecretCredential,
  kid: string,
  alg: "ES256",
  bytes: Uint8Array
}

export const signWithKey = async ({ credential, kid, alg, bytes }: RequestSignWithKey) => {
  if (alg !== 'ES256'){
    throw new Error('Only ES256 is supported.')
  }
  const [vaultUrl, keyPath] = kid.split('/keys/')
  const client = new KeyClient(vaultUrl, credential);
  const [keyName] = keyPath.split('/')
  const key = await client.getKey(keyName);
  const cryptographyClient = new CryptographyClient(key, credential);
  const hash = createHash("sha256");
  const digest = hash.update(bytes).digest();
  const signResult = await cryptographyClient.sign(alg, digest);
  return signResult.result
}


