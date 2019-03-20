import "babel-polyfill";
import {pbkdf2Sync as pbkdf2} from 'pbkdf2'
import bip32 from 'bip32';
import bip39 from 'bip39';
import ed25519 from 'ed25519';
import bs58 from 'bs58';

const Buffer = require("buffer").Buffer;
const hd_path = "m/44'/19'/2'/5";
const passphrase = "mnemoniccrosspool";

function mnemonicToSeed (mnemonic) {
   let mnemonicBuffer = Buffer.from(mnemonic, 'utf8');
   let saltBuffer = Buffer.from(passphrase, 'utf8');
   return pbkdf2(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512');
}

const run = async() => {

   let mnemonic = bip39.generateMnemonic();
   console.log("mnemonic is:", mnemonic);

   let seed = mnemonicToSeed(mnemonic);
   let master = bip32.fromSeed(seed);
   let xpnode = master.derivePath(hd_path);
   let xpseed = xpnode.privateKey;
   console.log("xpseed is:", xpseed.toString('hex'));

   let keyPair = ed25519.MakeKeypair(xpseed);
   console.info("private key is:", bs58.encode(keyPair.privateKey));
   let pk = keyPair.publicKey;
   console.info("public key is:", bs58.encode(pk));

   let did = bs58.encode(pk.slice(0, 16));
   console.info("public address (DID) is:", did);
};

run().catch(e=>{console.error(e.stack);});
