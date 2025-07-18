"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Utils_1 = require("../Utils");
class Musig {
    constructor(secp, key, sessionId, publicKeys) {
        this.secp = secp;
        this.key = key;
        this.sessionId = sessionId;
        this.publicKeys = publicKeys;
        this.numParticipants = () => {
            return this.publicKeys.length;
        };
        this.getAggregatedPublicKey = () => {
            return Buffer.from(this.pubkeyAgg.aggPubkey);
        };
        this.getPublicNonce = () => {
            return this.nonce.pubNonce;
        };
        this.tweakKey = (tweak) => {
            const tweaked = this.secp.musig.pubkeyXonlyTweakAdd(this.pubkeyAgg.keyaggCache, tweak, true);
            this.pubkeyAgg.keyaggCache = tweaked.keyaggCache;
            return Buffer.from(tweaked.pubkey);
        };
        this.aggregateNoncesOrdered = (nonces) => {
            if (this.publicKeys.length !== nonces.length) {
                throw 'number of nonces != number of public keys';
            }
            const myNonceIndex = nonces.findIndex((nonce) => Buffer.from(this.nonce.pubNonce).equals(Buffer.from(nonce)));
            if (myNonceIndex !== this.myIndex) {
                throw 'our nonce is at incorrect index';
            }
            this.pubNonces = nonces;
            this.nonceAgg = this.secp.musig.nonceAgg(nonces);
        };
        this.aggregateNonces = (nonces) => {
            if (nonces.find(([keyCmp]) => Buffer.from(this.key.publicKey).equals(keyCmp)) === undefined) {
                nonces.push([this.key.publicKey, this.getPublicNonce()]);
            }
            if (this.publicKeys.length !== nonces.length) {
                throw 'number of nonces != number of public keys';
            }
            const ordered = [];
            for (const key of this.publicKeys) {
                const nonce = nonces.find(([keyCmp]) => Buffer.from(key).equals(keyCmp));
                if (nonce === undefined) {
                    throw `could not find nonce for public key ${(0, Utils_1.getHexString)(key)}`;
                }
                ordered.push(nonce[1]);
            }
            this.aggregateNoncesOrdered(ordered);
        };
        this.initializeSession = (msg) => {
            if (this.nonceAgg === undefined) {
                throw 'nonces not aggregated';
            }
            if (this.session !== undefined) {
                throw 'session already initialized';
            }
            this.session = this.secp.musig.nonceProcess(this.nonceAgg, msg, this.pubkeyAgg.keyaggCache);
        };
        /**
         * Returns our partial signature and adds it to the internal list
         */
        this.signPartial = () => {
            if (this.session === undefined) {
                throw 'session not initialized';
            }
            const sig = this.secp.musig.partialSign(this.nonce.secNonce, this.key.privateKey, this.pubkeyAgg.keyaggCache, this.session);
            this.partialSignatures[this.myIndex] = sig;
            return sig;
        };
        this.verifyPartial = (publicKeyOrIndex, signature) => {
            if (this.pubNonces === undefined) {
                throw 'public nonces missing';
            }
            if (this.session === undefined) {
                throw 'session not initialized';
            }
            const publicKey = typeof publicKeyOrIndex === 'number'
                ? this.publicKeys[publicKeyOrIndex]
                : publicKeyOrIndex;
            const index = this.indexOfPublicKeyOrIndex(publicKey);
            return this.secp.musig.partialVerify(signature, this.pubNonces[index], publicKey, this.pubkeyAgg.keyaggCache, this.session);
        };
        /**
         * Adds a partial signature after verifying it
         */
        this.addPartial = (publicKeyOrIndex, signature) => {
            if (!this.verifyPartial(publicKeyOrIndex, signature)) {
                throw 'invalid partial signature';
            }
            this.partialSignatures[this.indexOfPublicKeyOrIndex(publicKeyOrIndex)] =
                signature;
        };
        this.aggregatePartials = () => {
            if (this.session === undefined) {
                throw 'session not initialized';
            }
            if (this.partialSignatures.some((partial) => partial === null)) {
                throw 'not all partial signatures are set';
            }
            return Buffer.from(this.secp.musig.partialSigAgg(this.session, this.partialSignatures));
        };
        this.indexOfPublicKeyOrIndex = (publicKeyOrIndex) => {
            const index = typeof publicKeyOrIndex === 'number'
                ? publicKeyOrIndex
                : this.publicKeys.findIndex((key) => publicKeyOrIndex.equals(key));
            if (index === -1) {
                throw `could not find index of public key ${(0, Utils_1.getHexString)(Buffer.from(publicKeyOrIndex))}`;
            }
            if (index > this.publicKeys.length - 1) {
                throw 'index out of range';
            }
            return index;
        };
        if (publicKeys.length < 2) {
            throw 'need at least 2 keys to aggregate';
        }
        this.myIndex = this.publicKeys.findIndex((key) => Buffer.from(this.key.publicKey).equals(key));
        if (this.myIndex === -1) {
            throw 'our key is not publicKeys';
        }
        this.pubkeyAgg = this.secp.musig.pubkeyAgg(publicKeys);
        this.nonce = this.secp.musig.nonceGen(sessionId, this.key.publicKey);
        this.partialSignatures = Array(publicKeys.length).fill(null);
    }
}
Musig.parsePubNonce = (nonce) => (0, Utils_1.getHexBuffer)(nonce);
exports.default = Musig;
//# sourceMappingURL=Musig.js.map