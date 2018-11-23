
import * as crypto from "crypto";
import { keccak256 } from "js-sha3";
import * as baseX from "base-x";

export function generate() {
    const ecdh = crypto.createECDH("secp256k1");
    ecdh.generateKeys();

    const privkey = ecdh.getPrivateKey();
    const pubKey = ecdh.getPublicKey()

    const addrBytes = Buffer.from("41" + keccak256(pubKey.slice(1)).substring(24), "hex");
    const checkSum = sha256(sha256(addrBytes)).slice(0, 4);
    const addrWithChecksum = Buffer.concat([addrBytes, checkSum]);
    const addr = base58.encode(addrWithChecksum);

    return {
        privateKey: privkey.toString("hex"),
        address: addr,
        // password: privkey.toString("base64"),
    };
}

function sha256(msg: Buffer): Buffer {
    return crypto.createHash("sha256").update(msg).digest();
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const base58 = baseX(BASE58_ALPHABET);
