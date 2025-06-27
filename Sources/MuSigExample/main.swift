#!/usr/bin/env swift

import Foundation
import P256K
import CryptoKit

// Hardcoded private keys for comparison (same as TypeScript example)
let OUR_PRIVATE_KEY_HEX = "4eef81683b17af3a61078093c6f75b71e9d0c971f438ec464e42bcf9eb171ea8"
let THEIR_PRIVATE_KEY_HEX = "2222222222222222222222222222222222222222222222222222222222222222"
let HARDCODED_SEED_HEX = "12345678901234567890123456789012"

print("🚀 Starting Hardcoded MuSig2 Reference Test (Swift)...\n")

// Convert hex strings to Data
guard let ourPrivateKeyData = Data(hexString: OUR_PRIVATE_KEY_HEX),
      let theirPrivateKeyData = Data(hexString: THEIR_PRIVATE_KEY_HEX),
      let hardcodedSeedData = Data(hexString: HARDCODED_SEED_HEX) else {
    print("❌ Failed to parse hex strings")
    exit(1)
}

print("✅ Hex strings parsed successfully")

do {
    // Create private keys from the hardcoded data
    let ourPrivateKey = try P256K.Schnorr.PrivateKey(dataRepresentation: ourPrivateKeyData)
    let theirPrivateKey = try P256K.Schnorr.PrivateKey(dataRepresentation: theirPrivateKeyData)
    
    // Get public keys
    let ourPublicKey = ourPrivateKey.publicKey
    let theirPublicKey = theirPrivateKey.publicKey
    
    print("=== KEY PAIRS ===")
    print("Our private key: \(OUR_PRIVATE_KEY_HEX)")
    print("Our public key: \(ourPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    print("Their private key: \(THEIR_PRIVATE_KEY_HEX)")
    print("Their public key: \(theirPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    
    // Aggregate public keys without sorting
    let publicKeys = [ourPublicKey, theirPublicKey]
    let aggregatedPublicKey = try P256K.MuSig.aggregate(publicKeys, sortKeys: false)
    
    print("\n=== AGGREGATED PUBLIC KEY ===")
    print("Aggregated public key: \(aggregatedPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

    let tweak = try! "20835eb2da4ae55e80d7b8d88af43c7ab7b1ffcd0030ad9675634869ca401d04ddad02ab04b1".bytes
    let tweakedKey = try! aggregatedPublicKey.add(tweak)

    print("\n=== TWEAKED PUBLIC KEY ===")
    print("Tweaked public key: \(tweakedKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

    // Generate nonces for each signer
    let firstNonce = try P256K.MuSig.Nonce.generate(
        secretKey: ourPrivateKey,
        publicKey: ourPublicKey,
        msg32: Array(hardcodedSeedData)  // Using the hardcoded seed as the message
    )

    // Example: Import an external nonce from a hex string
    let externalNonceHex = "024b7027d6a4fa3fc8ce8d81f77304ef893d96ac0aa6e4acffbb78d5d4dc162ad403dded4e0d1c190b19163e4475e711b70dc685ebf92ed2c4d57ab177fee97d7691"
    let externalNonce = try P256K.Schnorr.Nonce(hexString: externalNonceHex)
    
    // Aggregate with the external nonce
    let aggregateWithExternal = try P256K.MuSig.Nonce(aggregating: [firstNonce.pubnonce, externalNonce])

    print("\n=== NONCES ===")
    print("First Public Nonce: \(firstNonce.hexString)")
    print("External Nonce: \(externalNonce.hexString)")
    print("Aggregate with External: \(aggregateWithExternal.hexString)")

    // Create partial signatures
    let messageHash = Data(hexString: "101ff225c7506c82ea0285dafd2571360ed5831ef0b3580b57fefeb2e90aec99")!
    
    let firstPartialSignature = try ourPrivateKey.partialSignature(
        for: messageHash,
        pubnonce: firstNonce.pubnonce,
        secureNonce: firstNonce.secnonce,
        publicNonceAggregate: aggregateWithExternal,
        publicKeyAggregate: tweakedKey
    )

    print("\n=== PARTIAL SIGNATURES ===")
    print("First Partial Signature: \(firstPartialSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

    // Import external partial signature
    let externalPartialSignatureHex = "96201110389eccddf0bec127b94e1aaa594db401f2472fc8945ba51124b9c0a9"
    let externalPartialSignature = try P256K.Schnorr.PartialSignature(hexString: externalPartialSignatureHex)

    print("External Partial Signature: \(externalPartialSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

    let aggregateSignature = try P256K.MuSig.aggregateSignatures([firstPartialSignature, externalPartialSignature])

    print("Aggregate Signature: \(aggregateSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
} catch {
    print("❌ Error: \(error)")
    exit(1)
}

// Helper extension to parse hex strings
extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            let bytes = hexString[i..<j]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
            i = j
        }
        self = data
    }
} 
