import Foundation
import P256K

// Extension to create Data from hex string
extension Data {
    init?(hex: String) {
        let len = hex.count / 2
        var data = Data(capacity: len)
        var i = hex.startIndex
        for _ in 0..<len {
            let j = hex.index(i, offsetBy: 2)
            let bytes = hex[i..<j]
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

// Complete MuSig multi-signature scheme example (based on Boltz swap pattern)
func runMusigExample() throws {
    let hexPrivateKey = try "af40346aa48a361898b897e496ecbee8d5db1a09c9db3afd2d96aeef67fb6916".bytes
    let boltzServerPublicKeyBytes = try "0381ebb2034c76d0888bc255ce273cf99e7e366f8312b006ab279c1234a94ea0b8".bytes

    let boltzServerPublicKey = try! P256K.Schnorr.PublicKey(dataRepresentation: boltzServerPublicKeyBytes, format: .compressed)
    let ourPrivateKey = try! P256K.Schnorr.PrivateKey.init(dataRepresentation: hexPrivateKey)

    // Boltz swaps pre-date the finalizing of BIP-341 and their sorting is like this; always their own key first, your own key second
    let publicKeys = [boltzServerPublicKey, ourPrivateKey.publicKey]
    let aggregatedPublicKey = try P256K.MuSig.aggregate(publicKeys, sortKeys: false)

    let claimLeafOutputHex = "82012088a914a99c12a49ca2886c021870136f0f74c55e7336558820c970e36ade0dd4f7e52eb8d053ed7d27adf692af37c37fa39a2a10a71aad777bac"
    let refundLeafOutputHex = "2081ebb2034c76d0888bc255ce273cf99e7e366f8312b006ab279c1234a94ea0b8ad025c01b1"

    // Now comes the tweaking of the key, which is more less what is done in this test: https://github.com/21-DOT-DEV/swift-secp256k1/blob/main/Tests/ZKPTests/TaprootTests.swift#L42

    let claimLeafOutput = try claimLeafOutputHex.bytes
    let claimLeafHash = try SHA256.taggedHash(
        tag: "TapLeaf".data(using: .utf8)!,
        data: Data([0xC0]) + Data(claimLeafOutput).compactSizePrefix
    )

    // Create the refund leaf hash
    let refundLeafOutput = try refundLeafOutputHex.bytes
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

    // this tweakedXonlyKey is what appears in the script and what we can search the lockup transaction for
    let tweakedXonlyKey = try aggregatedPublicKey.xonly.add(Array(Data(tapTweakHash)))
    // I believe I can't do the partial signature if I use the tweakedXonlyKey so that's why I also tweak the full aggregatedPublicKey
    let tweakedAggregatedKey = try aggregatedPublicKey.add(Array(Data(tapTweakHash)))

    let lockupTxHex = "01000000000101af086a23a2c83a9b70319077297acb9ee237e061f53007361396ca8f2181303c0000000000ffffffff026f0aceb2000000002251202387f0c58732ab542bddb80357bb76b53f2f5b1c409ceb6ab3b0892eb4eb71663bc900000000000022512080ddf54159c4aa1e4380145ab74284ec65221bd4cc4194b40d663765e56e9a8b01403556a84e35a65142a74461af0119eb8445fc2a8ea77f635d8365f01fc1bdcc29591597e621788869b60fbcd2208ad45428bfccd2076487cd1b76feca51779d5600000000"

    // Some code beyond the scope of the library to detect the swap output in the lockupTx and calculate the sigHash (which is what has to be signed by both parties)
    // Considering I get the same results with Boltz Typescript reference implementation, I think this is fine
    let sigHash = "e74e462957d5eb0bed5e8ea4a6d49001c61bb97842c4e18cc1e1958cfe744bd8"

    let serializedTx = "010000000001012fd6b776e2cdb0e7740a02361eaf26b93feba3f4dd89b5e25cd45a1ef4b31d680100000000fdffffff0173c8000000000000160014b29fab16eafd21afe488f2959afff422eea2a1f401400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

    let messageHashBytes = try sigHash.bytes
    // As this is exactly what we want to sign, we don't SHA256 anything!

    // Generate nonces for each signer
    let firstNonce = try P256K.MuSig.Nonce.generate(
        secretKey: ourPrivateKey,
        publicKey: ourPrivateKey.publicKey,
        msg32: messageHashBytes
    )

    // Store hex string before nonce gets consumed
    let firstNonceHexString = firstNonce.hexString

    let swapID = "fQKVUtJUuL9H"
    let ourNonceHex = firstNonce.pubnonce.map { String(format: "%02x", $0) }.joined()
    let preimage = "89d3e7a8cb9ad1b1d33aebe80498fa519082e40cbcc12cf3cfc466b089c6f907"

    // Hardcoded Boltz response for testing
    let boltzPubNonce = "037447c1f04cba0403b692ddff24895dc0c171597549b821ca261af677a2ee22ea037c35bcb8d1e55137e7a52dcfde5ccc4623b12c65a2e9230bf4acfbb2fd0c9b68"
    let boltzPartialSignature = "4fbffff7ff8e294b57257a3f829e5676c86a5a9d00b671eb357b3c490380d12f"
    
    print("Received Boltz pubNonce: \(boltzPubNonce)")
    print("Received Boltz partialSignature: \(boltzPartialSignature)")
    
    print("\n=== SIGNING DETAILS ===")
    print("Message Digest (hex): \(Data(messageHashBytes).map { String(format: "%02x", $0) }.joined())")
    print("Tweaked Aggregated Public Key (hex): \(Data(tweakedAggregatedKey.xonly.bytes).map { String(format: "%02x", $0) }.joined())")
    
    // Convert to P256K objects
    let externalNonce = try P256K.Schnorr.Nonce(hexString: boltzPubNonce)
    let externalPartialSignatureBytes = try boltzPartialSignature.bytes
    
    // Aggregate with the external nonce
    let aggregateWithExternal = try P256K.MuSig.Nonce(aggregating: [externalNonce, firstNonce.pubnonce])
    
    print("\n=== NONCES ===")
    print("First Public Nonce: \(firstNonce.pubnonce.map { String(format: "%02x", $0) }.joined())")
    print("External Nonce: \(boltzPubNonce)")
    print("Aggregate with External: \(aggregateWithExternal.bytes.map { String(format: "%02x", $0) }.joined())")
    
    let digest = SHA256.hash(data: messageHashBytes)
    let firstPartialSignature = try ourPrivateKey.partialSignature(
        for: digest,
        pubnonce: firstNonce.pubnonce,
        secureNonce: firstNonce.secnonce,
        publicNonceAggregate: aggregateWithExternal,
        publicKeyAggregate: tweakedAggregatedKey
    )
    
    print("\n=== NONCES ===")
    print("First Public Nonce: \(firstNonceHexString)")
    print("External Nonce: \(externalNonce.hexString)")
    print("Aggregate Nonce with External: \(aggregateWithExternal.hexString)")

    let externalPartialSignature = try P256K.Schnorr.PartialSignature(hexString: boltzPartialSignature)
    
    print("\n=== PARTIAL SIGNATURES ===")
    print("First Partial Signature: \(firstPartialSignature.dataRepresentation.bytes.map { String(format: "%02x", $0) }.joined())")
    print("External Partial Signature: \(externalPartialSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    
    let aggregateSignature = try P256K.MuSig.aggregateSignatures([externalPartialSignature, firstPartialSignature])
    
    let aggregateSignatureHex = aggregateSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined()
    
    print("Aggregate Signature: \(aggregateSignatureHex)")
}

// Run the example
do {
    try runMusigExample()
} catch {
    print("Error: \(error)")
}