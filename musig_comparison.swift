#!/usr/bin/env swift

import Foundation

// Import the P256K library (assuming it's available)
// Note: In a real project, you would import this as a module
// import P256K

// Hardcoded private keys for comparison (same as TypeScript example)
let OUR_PRIVATE_KEY_HEX = "1111111111111111111111111111111111111111111111111111111111111111"
let THEIR_PRIVATE_KEY_HEX = "2222222222222222222222222222222222222222222222222222222222222222"
let HARDCODED_SEED_HEX = "3333333333333333333333333333333333333333333333333333333333333333"

print("🚀 Starting Hardcoded MuSig2 Reference Test (Swift)...\n")

// Convert hex strings to Data
guard let ourPrivateKeyData = Data(hexString: OUR_PRIVATE_KEY_HEX),
      let theirPrivateKeyData = Data(hexString: THEIR_PRIVATE_KEY_HEX),
      let hardcodedSeedData = Data(hexString: HARDCODED_SEED_HEX) else {
    print("❌ Failed to parse hex strings")
    exit(1)
}

print("✅ Hex strings parsed successfully")

// In a real implementation, you would use the P256K library like this:
/*
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

// Aggregate public keys
let publicKeys = [ourPublicKey, theirPublicKey]
let aggregatedPublicKey = try P256K.MuSig.aggregate(publicKeys)

print("\n=== AGGREGATED PUBLIC KEY ===")
print("Aggregated public key: \(aggregatedPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

// Create a message to sign (equivalent to the TypeScript example)
let message = "Hello, MuSig2!".data(using: .utf8)!
let messageHash = SHA256.hash(data: message)

print("\n=== MESSAGE ===")
print("Message: Hello, MuSig2!")
print("Message hash: \(messageHash.map { String(format: "%02x", $0) }.joined())")

// Generate nonces for each signer
let ourNonce = try P256K.MuSig.Nonce.generate(
    sessionID: Array(hardcodedSeedData),
    secretKey: ourPrivateKey,
    publicKey: ourPublicKey,
    msg32: Array(messageHash),
    extraInput32: nil
)

let theirNonce = try P256K.MuSig.Nonce.generate(
    sessionID: Array(hardcodedSeedData),
    secretKey: theirPrivateKey,
    publicKey: theirPublicKey,
    msg32: Array(messageHash),
    extraInput32: nil
)

print("\n=== NONCE GENERATION ===")
print("Session seed: \(HARDCODED_SEED_HEX)")
print("✅ Nonces generated successfully")

// Extract public nonces and aggregate them
let publicNonces = [ourNonce.pubnonce, theirNonce.pubnonce]
let aggregateNonce = try P256K.MuSig.Nonce(aggregating: publicNonces)

print("\n=== NONCE AGGREGATION ===")
print("✅ Public nonces aggregated successfully")

// Create partial signatures
let ourPartialSignature = try ourPrivateKey.partialSignature(
    for: messageHash,
    pubnonce: ourNonce.pubnonce,
    secureNonce: ourNonce.secnonce,
    publicNonceAggregate: aggregateNonce,
    publicKeyAggregate: aggregatedPublicKey
)

let theirPartialSignature = try theirPrivateKey.partialSignature(
    for: messageHash,
    pubnonce: theirNonce.pubnonce,
    secureNonce: theirNonce.secnonce,
    publicNonceAggregate: aggregateNonce,
    publicKeyAggregate: aggregatedPublicKey
)

print("\n=== PARTIAL SIGNATURES ===")
print("✅ Partial signatures created successfully")

// Aggregate partial signatures into final signature
let finalSignature = try P256K.MuSig.aggregateSignatures([ourPartialSignature, theirPartialSignature])

print("\n=== FINAL SIGNATURE ===")
print("Final signature: \(finalSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

// Verify the signature
let isValid = aggregatedPublicKey.xonly.verify(
    finalSignature,
    for: messageHash
)

print("\n=== VERIFICATION ===")
print("Signature verification: \(isValid ? "✅ SUCCESS" : "❌ FAILED")")

// For Bitcoin P2TR output (equivalent to TypeScript p2trOutput)
let outputScript = createP2TROutputScript(from: aggregatedPublicKey.xonly.bytes)
let amount = 10_000

print("\n=== BITCOIN OUTPUT ===")
print("Output script: \(outputScript.map { String(format: "%02x", $0) }.joined())")
print("Amount: \(amount) sats")

print("\n🎉 MuSig2 Swift implementation completed successfully!")
*/

// Since we can't actually run the P256K library in this script,
// let's show the equivalent structure and API calls:

print("=== SWIFT MUSIG2 API STRUCTURE ===")
print("""
// Key creation:
let ourPrivateKey = try P256K.Schnorr.PrivateKey(dataRepresentation: ourPrivateKeyData)
let theirPrivateKey = try P256K.Schnorr.PrivateKey(dataRepresentation: theirPrivateKeyData)

// Public key aggregation:
let publicKeys = [ourPrivateKey.publicKey, theirPrivateKey.publicKey]
let aggregatedPublicKey = try P256K.MuSig.aggregate(publicKeys)

// Nonce generation:
let ourNonce = try P256K.MuSig.Nonce.generate(
    sessionID: Array(hardcodedSeedData),
    secretKey: ourPrivateKey,
    publicKey: ourPrivateKey.publicKey,
    msg32: Array(messageHash),
    extraInput32: nil
)

// Nonce aggregation:
let publicNonces = [ourNonce.pubnonce, theirNonce.pubnonce]
let aggregateNonce = try P256K.MuSig.Nonce(aggregating: publicNonces)

// Partial signing:
let ourPartialSignature = try ourPrivateKey.partialSignature(
    for: messageHash,
    pubnonce: ourNonce.pubnonce,
    secureNonce: ourNonce.secnonce,
    publicNonceAggregate: aggregateNonce,
    publicKeyAggregate: aggregatedPublicKey
)

// Signature aggregation:
let finalSignature = try P256K.MuSig.aggregateSignatures([ourPartialSignature, theirPartialSignature])

// Verification:
let isValid = aggregatedPublicKey.xonly.verify(finalSignature, for: messageHash)
""")

print("\n=== COMPARISON WITH TYPESCRIPT ===")
print("""
TypeScript API:
- zkpInit.default() -> P256K.Context (implicit)
- ECPairFactory(ecc).fromPrivateKey() -> P256K.Schnorr.PrivateKey()
- musig.getAggregatedPublicKey() -> P256K.MuSig.aggregate()
- p2trOutput() -> createP2TROutputScript() (custom function)

Swift API:
- More explicit and type-safe
- Separate types for public/private keys, nonces, signatures
- Stronger compile-time guarantees
- Native Swift error handling with try/catch
""")

// Helper function to create P2TR output script
func createP2TROutputScript(from xonlyPubKey: [UInt8]) -> [UInt8] {
    // P2TR output script: OP_1 <32-byte x-only pubkey>
    return [0x51] + xonlyPubKey
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