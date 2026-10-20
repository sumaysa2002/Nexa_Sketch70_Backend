import { generateKeyPairSync } from "crypto";
import fs from "fs";
import path from "path";

const keysDir = path.join(process.cwd(), "keys");

if (!fs.existsSync(keysDir)) {
  fs.mkdirSync(keysDir);
}

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
});

fs.writeFileSync(path.join(keysDir, "access_private.pem"), privateKey);
fs.writeFileSync(path.join(keysDir, "access_public.pem"), publicKey);

console.log("✅ RSA keys created in /keys");
