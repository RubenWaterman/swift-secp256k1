#!/usr/bin/env swift

import Foundation
import P256K

// Hardcoded private keys for comparison (same as TypeScript example)
let OUR_PRIVATE_KEY_HEX = "1111111111111111111111111111111111111111111111111111111111111111"
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
