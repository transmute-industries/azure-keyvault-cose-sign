### COSE Signatures

#### with Azure Key Vault

[![CI](https://github.com/transmute-industries/azure-keyvault-cose-sign/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/azure-keyvault-cose-sign/actions/workflows/ci.yml)

## Usage

🔥 This package is not stable or suitable for production use 🚧

```bash
npm install '@transmute/azure-keyvault-cose-sign'
```

The following example is based on [draft-ietf-cose-hash-envelope](https://github.com/cose-wg/draft-ietf-cose-hash-envelope).

```ts
import * as cose from "@transmute/cose";
import * as akv from "@transmute/azure-keyvault-cose-sign";
const coseSign1 = await cose.hash
  .signer({
    remote: await akv.cose.remote({ credential, kid, alg: "ES256" }),
  })
  .sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Signature.ES256],
      [cose.Protected.PayloadHashAlgorithm, cose.Hash.SHA256],
      [cose.Protected.PayloadPreImageContentType, "application/spdx+json"],
      [
        cose.Protected.PayloadLocation,
        "https://<ACCOUNT>.blob.core.windows.net/<PATH>/<FILENAME>",
      ],
    ]),
    payload,
  });
// const publicKeyJwk = await api.jose.getPublicKey({credential, kid})
const publicKeyJwk = {
  kid: "https://<ACCOUNT>>.vault.azure.net/keys/<KEY-NAME>/5de5b...a9ea0",
  kty: "EC",
  crv: "P-256",
  alg: "ES256",
  x: "QgiOQd35ffsDYAKL1C0Fhxc4R5wdxDXeM3o0CYuyTvY",
  y: "_Pb10s5m-BHeEgnwFt6BvhGldMKgW_wuoK1OBi4y5M8",
};
const verified = await akv.cose.verifier({ publicKeyJwk }).verify({
  coseSign1,
});
// const verified = await akv.cose.verifier({ credential, kid }).verify({
//   coseSign1,
// });
// expect(Buffer.from(verified).toString('hex')).toBe("ed5fd4988b349c02e8a05926ff26ab09e6ab0a7ab7c22b785e8c7320f080885f")
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```

### Setting Up Azure Key Vault

You may find these commands helpful on macOS:

```bash
softwareupdate --install-rosetta
brew tap azure/azd && brew install azd
azd auth login --use-device-code
```
