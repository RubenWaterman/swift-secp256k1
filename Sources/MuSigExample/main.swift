#!/usr/bin/env swift

import Foundation
import P256K
import CryptoKit
import Crypto

// Hardcoded private keys for comparison (same as TypeScript example)
let OUR_PRIVATE_KEY_HEX = "f1709ec6ca1e8f06508a3d2c23b7503b6457c1fe60ecac46ab0ebf4082a2c640"
let THEIR_PUBLIC_KEY_HEX = "03d0ceae7a2076302b7418fd8ad1c8e6f05cb5e8f24116813074e1fb4e87d3b523"
let HARDCODED_SEED_HEX = "12345678901234567890123456789012"

print("🚀 Starting Hardcoded MuSig2 Reference Test (Swift)...\n")

// Convert hex strings to Data
guard let ourPrivateKeyData = Data(hexString: OUR_PRIVATE_KEY_HEX),
      let theirPublicKeyData = Data(hexString: THEIR_PUBLIC_KEY_HEX),
      let hardcodedSeedData = Data(hexString: HARDCODED_SEED_HEX) else {
    print("❌ Failed to parse hex strings")
    exit(1)
}

print("✅ Hex strings parsed successfully")

do {
    // Create private keys from the hardcoded data
    let ourPrivateKey = try P256K.Schnorr.PrivateKey(dataRepresentation: ourPrivateKeyData)

    let boltzServerPublicKey = try! P256K.Schnorr.PublicKey(
        dataRepresentation: theirPublicKeyData,
        format: .compressed
    )
    
    // Get public keys
    let ourPublicKey = ourPrivateKey.publicKey
    
    print("=== KEY PAIRS ===")
    print("Our private key: \(OUR_PRIVATE_KEY_HEX)")
    print("Our public key: \(ourPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    print("Their public key: \(boltzServerPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    
    // Aggregate public keys without sorting
    let publicKeys = [ourPublicKey, boltzServerPublicKey]
    let aggregatedPublicKey = try P256K.MuSig.aggregate(publicKeys, sortKeys: false)
    
    print("\n=== AGGREGATED PUBLIC KEY ===")
    print("Aggregated public key: \(aggregatedPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    print("Aggregated x-only public key: \(aggregatedPublicKey.xonly.bytes.map { String(format: "%02x", $0) }.joined())")

    // --- BIP-341 Taproot tweak computation using swapTree ---
    // Based on the swapTree structure from the API response:
    // swapTree = {
    //     claimLeaf = {
    //         output = a91439aa8f251488b1a02fc89fe448f9bbf45a3b01f48820d0ceae7a2076302b7418fd8ad1c8e6f05cb5e8f24116813074e1fb4e87d3b523ac;
    //         version = 192;
    //     };
    //     refundLeaf = {
    //         output = 20f8b2dfc86aa1f5c6df0d3089c74088eaf0527216b61472113e8839e4e4bbb69fad02c004b1;
    //         version = 192;
    //     };
    // };
    
    // Create the claim leaf hash
    let claimLeafOutput = try "a91439aa8f251488b1a02fc89fe448f9bbf45a3b01f48820d0ceae7a2076302b7418fd8ad1c8e6f05cb5e8f24116813074e1fb4e87d3b523ac".bytes
    let claimLeafHash = try SHA256.taggedHash(
        tag: "TapLeaf".data(using: .utf8)!,
        data: Data([0xC0]) + Data(claimLeafOutput).compactSizePrefix
    )
    
    // Create the refund leaf hash
    let refundLeafOutput = try "20f8b2dfc86aa1f5c6df0d3089c74088eaf0527216b61472113e8839e4e4bbb69fad02c004b1".bytes
    let refundLeafHash = try SHA256.taggedHash(
        tag: "TapLeaf".data(using: .utf8)!,
        data: Data([0xC0]) + Data(refundLeafOutput).compactSizePrefix
    )
    
    // Sort the leaves lexicographically and create the merkle root
    var leftHash, rightHash: Data
    if claimLeafHash < refundLeafHash {
        leftHash = Data(claimLeafHash)
        rightHash = Data(refundLeafHash)
    } else {
        leftHash = Data(refundLeafHash)
        rightHash = Data(claimLeafHash)
    }
    
    let merkleRoot = try SHA256.taggedHash(
        tag: "TapBranch".data(using: .utf8)!,
        data: leftHash + rightHash
    )
    
    // Create the tap tweak hash using the x-only public key and merkle root
    let xOnlyPubKey = aggregatedPublicKey.xonly.bytes
    let tapTweakHash = try SHA256.taggedHash(
        tag: "TapTweak".data(using: .utf8)!,
        data: Data(xOnlyPubKey) + Data(merkleRoot)
    )
    
    print("\n=== TAPROOT TWEAK COMPUTATION ===")
    print("X-only public key for tweak: \(xOnlyPubKey.map { String(format: "%02x", $0) }.joined())")
    print("Claim leaf hash: \(Data(claimLeafHash).map { String(format: "%02x", $0) }.joined())")
    print("Refund leaf hash: \(Data(refundLeafHash).map { String(format: "%02x", $0) }.joined())")
    print("Merkle root: \(Data(merkleRoot).map { String(format: "%02x", $0) }.joined())")
    print("Tap tweak hash: \(Data(tapTweakHash).map { String(format: "%02x", $0) }.joined())")
    
    // Apply the x-only tweak to the aggregated public key's x-only key
    // For Taproot, we need to use x-only tweaking which properly updates the key aggregation cache
    let tweakedXonlyKey = try aggregatedPublicKey.xonly.add(Array(Data(tapTweakHash)))
    
    // Create a new MuSig public key from the tweaked x-only key (preserves the cache)
    let tweakedKey = try aggregatedPublicKey.add(Array(Data(tapTweakHash)))
    print("Sharon's key: \(tweakedKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

    
    print("\n=== TWEAKED PUBLIC KEY ===")
    print("Tweaked x-only public key: \(tweakedXonlyKey.bytes.map { String(format: "%02x", $0) }.joined())")
    print("Expected result: 31b27adafdcc9635f3a7c3e25e248979508960ffb9b1ca89d6d95fb2992a6858")

    // Generate nonces for each signer
    let firstNonce = try P256K.MuSig.Nonce.generate(
        secretKey: ourPrivateKey,
        publicKey: ourPublicKey,
        msg32: Array(hardcodedSeedData)  // Using the hardcoded seed as the message
    )

    // Make API call to get refund partial signature from Boltz
    let refundEndpoint = "https://api.regtest.getbittr.com/v2/swap/submarine/t6qPA5n7IAIQ/refund"
    
    let requestBody: [String: Any] = [
        "pubNonce": firstNonce.pubnonce.map { String(format: "%02x", $0) }.joined(),
        "transaction": "0100000001ee230c9cc65e420c8b10d092d3ba31502111461fbc7211c0f0c5bb00bac527290100000000ffffffff014e0b0300000000001600143e883ffc3ad8b0d30588d9c7d0fb0e7053318d0c00000000", // We'll use a placeholder for now
        "index": 0
    ]
    
    print("📡 Making refund API call to: \(refundEndpoint)")
    print("📡 Request body: \(requestBody)")
    
    let refundUrl = URL(string: refundEndpoint)!
    var refundRequest = URLRequest(url: refundUrl)
    refundRequest.httpMethod = "POST"
    refundRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
    refundRequest.setValue("application/json", forHTTPHeaderField: "Accept")
    refundRequest.httpBody = try JSONSerialization.data(withJSONObject: requestBody)
    
    // Add timeout
    refundRequest.timeoutInterval = 10.0
    
    if #available(iOS 15.0, macOS 12.0, *) {
        let (refundData, refundResponse) = try await URLSession.shared.data(for: refundRequest)
        print("📡 Refund Response Status: \((refundResponse as? HTTPURLResponse)?.statusCode ?? 0)")
        print("📡 Refund Raw Response: \(String(data: refundData, encoding: .utf8) ?? "Unable to decode")")
        
        // Try to parse the response
        if let refundJson = try? JSONSerialization.jsonObject(with: refundData) as? [String: Any] {
            print("✅ Refund response parsed successfully:")
            for (key, value) in refundJson {
                print("  \(key): \(value)")
            }
            
            // Extract pubNonce and partialSignature from the API response
            if let pubNonceString = refundJson["pubNonce"] as? String,
               let partialSignatureString = refundJson["partialSignature"] as? String {
                
                print("📋 Extracted pubNonce: \(pubNonceString)")
                print("📋 Extracted partialSignature: \(partialSignatureString)")
                
                // Convert to P256K objects
                let externalNonce = try P256K.Schnorr.Nonce(hexString: pubNonceString)
                let externalPartialSignature = try P256K.Schnorr.PartialSignature(hexString: partialSignatureString)
                
                // Aggregate with the external nonce
                let aggregateWithExternal = try P256K.MuSig.Nonce(aggregating: [firstNonce.pubnonce, externalNonce])

                print("\n=== NONCES ===")
                print("First Public Nonce: \(firstNonce.hexString)")
                print("External Nonce: \(externalNonce.hexString)")
                print("Aggregate with External: \(aggregateWithExternal.hexString)")

                // Create partial signatures
                let messageHashHex = "eaf0e495a005cf74b0578e16f638f195d1e1056150a40b654be2df0f2caa1920"
                let messageHashBytes = try messageHashHex.bytes
                let messageDigest = HashDigest(messageHashBytes)
                
                let firstPartialSignature = try ourPrivateKey.partialSignature(
                    for: messageDigest,
                    pubnonce: firstNonce.pubnonce,
                    secureNonce: firstNonce.secnonce,
                    publicNonceAggregate: aggregateWithExternal,
                    publicKeyAggregate: tweakedKey
                )

                dump(firstPartialSignature)

                print("\n=== PARTIAL SIGNATURES ===")
                print("First Partial Signature: \(firstPartialSignature.dataRepresentation.bytes.map { String(format: "%02x", $0) }.joined())")
                print("External Partial Signature: \(externalPartialSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

                let aggregateSignature = try P256K.MuSig.aggregateSignatures([firstPartialSignature, externalPartialSignature])

                print("Aggregate Signature: \(aggregateSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
                
                // Test the new parsing function
                print("\n=== TESTING NONCE PARSING ===")
                let exampleHexString = "0330d9609e16de90cf7d668d68025a1a1cb4107851a9379cb5b313914ddfb36913020c42d220b2ad6cc0490a0cf51ce8b3fb41a8ec1149c3cdfe860b671189e4efc6"
                
                do {
                    let parsedNonce = try P256K.MuSig.Nonce.parse(hexString: exampleHexString)
                    print("Successfully parsed nonce from hex string")
                    print("Parsed nonce hex: \(parsedNonce.hexString)")
                    print("Original hex:     \(exampleHexString)")
                    print("Match: \(parsedNonce.hexString == exampleHexString)")
                } catch {
                    print("Failed to parse nonce: \(error)")
                }
                
                // Test the tap tweak hash computation
                print("\n=== TESTING TAP TWEAK HASH COMPUTATION ===")
                let claimLeafOutput = "82012088a914772e71cb02fdf4430127ba1239539dd7e2375a838820f8b2dfc86aa1f5c6df0d3089c74088eaf0527216b61472113e8839e4e4bbb69fac"
                let refundLeafOutput = "82012088a914772e71cb02fdf4430127ba1239539dd7e2375a838820f8b2dfc86aa1f5c6df0d3089c74088eaf0527216b61472113e8839e4e4bbb69fac"
                
                do {
                    let tapTweakHash = try computeTapTweakHash(claimLeafOutput: claimLeafOutput, refundLeafOutput: refundLeafOutput)
                    print("Claim leaf output: \(claimLeafOutput)")
                    print("Refund leaf output: \(refundLeafOutput)")
                    print("Tap tweak hash: \(tapTweakHash.map { String(format: "%02x", $0) }.joined())")
                } catch {
                    print("Failed to compute tap tweak hash: \(error)")
                }
                
            } else {
                print("❌ Could not extract pubNonce or partialSignature from refund response")
            }
        }        
    } else {
        // Fallback on earlier versions
    }
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

extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// Helper extension to parse hex strings
extension String {
    var bytes: [UInt8] {
        var bytes: [UInt8] = []
        var index = startIndex
        while index < endIndex {
            let nextIndex = self.index(index, offsetBy: 2, limitedBy: endIndex) ?? endIndex
            let hexByte = String(self[index..<nextIndex])
            if let byte = UInt8(hexByte, radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return bytes
    }
}

extension Data {
    init(hexString: String) throws {
        guard hexString.count % 2 == 0 else {
            throw secp256k1Error.underlyingCryptoError
        }
        
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2, limitedBy: hexString.endIndex) ?? hexString.endIndex
            let hexByte = String(hexString[index..<nextIndex])
            guard let byte = UInt8(hexByte, radix: 16) else {
                throw secp256k1Error.underlyingCryptoError
            }
            bytes.append(byte)
            index = nextIndex
        }
        self.init(bytes)
    }
}

/// Computes the tap tweak hash from claim and refund leaf outputs according to BIP-341
/// - Parameters:
///   - claimLeafOutput: Hex string of the claim leaf output script
///   - refundLeafOutput: Hex string of the refund leaf output script
/// - Returns: The tap tweak hash as a Data object
func computeTapTweakHash(claimLeafOutput: String, refundLeafOutput: String) throws -> Data {
    // Convert hex strings to Data
    let claimScript = try Data(hexString: claimLeafOutput)
    let refundScript = try Data(hexString: refundLeafOutput)
    
    // Compute TapLeaf hashes with tagged hash
    // TapLeaf = hash(0xc0 || compact_size(script_len) || script)
    let claimTapLeaf = computeTapLeafHash(script: claimScript)
    let refundTapLeaf = computeTapLeafHash(script: refundScript)
    
    // Sort the leaves lexicographically (BIP-341 requirement)
    let sortedLeaves: [Data]
    if claimTapLeaf < refundTapLeaf {
        sortedLeaves = [claimTapLeaf, refundTapLeaf]
    } else {
        sortedLeaves = [refundTapLeaf, claimTapLeaf]
    }
    
    // Compute TapBranch hash
    // TapBranch = hash(0xc1 || left_hash || right_hash)
    let tapBranch = computeTapBranchHash(left: sortedLeaves[0], right: sortedLeaves[1])
    
    return tapBranch
}

/// Computes a TapLeaf hash according to BIP-341
/// - Parameter script: The script to hash
/// - Returns: The TapLeaf hash
private func computeTapLeafHash(script: Data) -> Data {
    // Tagged hash: SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || data)
    let tag = "TapLeaf".data(using: .utf8)!
    let tagHash = SHA256.hash(data: tag)
    
    // Compact size encoding for script length
    let scriptLen = script.count
    var compactSize: Data
    if scriptLen < 0xfd {
        compactSize = Data([UInt8(scriptLen)])
    } else if scriptLen <= 0xffff {
        compactSize = Data([0xfd]) + Data(withUnsafeBytes(of: UInt16(scriptLen).littleEndian) { Data($0) })
    } else if scriptLen <= 0xffffffff {
        compactSize = Data([0xfe]) + Data(withUnsafeBytes(of: UInt32(scriptLen).littleEndian) { Data($0) })
    } else {
        compactSize = Data([0xff]) + Data(withUnsafeBytes(of: UInt64(scriptLen).littleEndian) { Data($0) })
    }
    
    // TapLeaf = hash(tag_hash || tag_hash || compact_size || script)
    let input = tagHash + tagHash + compactSize + script
    return Data(SHA256.hash(data: input))
}

/// Computes a TapBranch hash according to BIP-341
/// - Parameters:
///   - left: The left child hash
///   - right: The right child hash
/// - Returns: The TapBranch hash
private func computeTapBranchHash(left: Data, right: Data) -> Data {
    // Tagged hash: SHA256(SHA256("TapBranch") || SHA256("TapBranch") || data)
    let tag = "TapBranch".data(using: .utf8)!
    let tagHash = SHA256.hash(data: tag)
    
    // TapBranch = hash(tag_hash || tag_hash || left_hash || right_hash)
    let input = tagHash + tagHash + left + right
    return Data(SHA256.hash(data: input))
}
