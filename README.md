[![Build Status](https://app.bitrise.io/app/18c18db60fc4fddf/status.svg?token=nczB4mTPCrlTfDQnXH_8Pw&branch=main)](https://app.bitrise.io/app/18c18db60fc4fddf) [![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2F21-DOT-DEV%2Fswift-secp256k1%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/21-DOT-DEV/swift-secp256k1) [![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2F21-DOT-DEV%2Fswift-secp256k1%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/21-DOT-DEV/swift-secp256k1)

# 🔐 swift-secp256k1

Swift package for elliptic curve public key cryptography, ECDSA, and Schnorr Signatures for Bitcoin, with C bindings from [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

## Objectives

- Provide lightweight ECDSA & Schnorr Signatures functionality
- Support simple and advanced usage, including BIP-327 and BIP-340
- Expose libsecp256k1 bindings for full control of the implementation
- Offer a familiar API design inspired by [Swift Crypto](https://github.com/apple/swift-crypto)
- Maintain automatic updates for Swift and libsecp256k1
- Ensure availability for Linux and Apple platform ecosystems

## Installation

This package uses Swift Package Manager. To add it to your project:

> [!WARNING]  
> These APIs are not considered stable and may change with any update. Specify a version using `exact:` to avoid breaking changes.

### Using Xcode

1. Go to `File > Add Packages...`
2. Enter the package URL: `https://github.com/21-DOT-DEV/swift-secp256k1`
3. Select the desired version

### Using Package.swift (Recommended)

Add the following to your `Package.swift` file:

```swift
.package(name: "swift-secp256k1", url: "https://github.com/21-DOT-DEV/swift-secp256k1", from: "0.21.1"),
```

Then, include `P256K` as a dependency in your target:

```swift
.target(name: "<target>", dependencies: [
    .product(name: "P256K", package: "swift-secp256k1")
]),
```

### Using CocoaPods

Add the following to your `Podfile`:

```ruby
pod 'swift-secp256k1', '0.21.1'
```

### Try it out

Use [SPI Playgrounds app](https://swiftpackageindex.com/try-in-a-playground):

```swift
arena 21-DOT-DEV/swift-secp256k1
```

## Usage Examples

### ECDSA
```swift
import P256K

// Private key
let privateBytes = try! "14E4A74438858920D8A35FB2D88677580B6A2EE9BE4E711AE34EC6B396D87B5C".bytes
let privateKey = try! P256K.Signing.PrivateKey(dataRepresentation: privateBytes)

// Public key
print(String(bytes: privateKey.publicKey.dataRepresentation))

// ECDSA signature
let messageData = "We're all Satoshi.".data(using: .utf8)!
let signature = try! privateKey.signature(for: messageData)

// DER signature
print(try! signature.derRepresentation.base64EncodedString())
```

### Schnorr
```swift
// Strict BIP340 mode is disabled by default for Schnorr signatures with variable length messages
let privateKey = try! P256K.Schnorr.PrivateKey()

// Extra params for custom signing
var auxRand = try! "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906".bytes
var messageDigest = try! "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C".bytes

// API allows for signing variable length messages
let signature = try! privateKey.signature(message: &messageDigest, auxiliaryRand: &auxRand)
```

### Tweak

```swift
let privateKey = try! P256K.Signing.PrivateKey()

// Adding a tweak to the private key and public key
let tweak = try! "5f0da318c6e02f653a789950e55756ade9f194e1ec228d7f368de1bd821322b6".bytes
let tweakedPrivateKey = try! privateKey.add(tweak)
let tweakedPublicKeyKey = try! privateKey.publicKey.add(tweak)
```

### Elliptic Curve Diffie Hellman

```swift
let privateKey = try! P256K.KeyAgreement.PrivateKey()
let publicKey = try! P256K.KeyAgreement.PrivateKey().publicKey

// Create a compressed shared secret with a private key from only a public key
let sharedSecret = try! privateKey.sharedSecretFromKeyAgreement(with: publicKey, format: .compressed)

// By default, libsecp256k1 hashes the x-coordinate with version information.
let symmetricKey = SHA256.hash(data: sharedSecret.bytes)
```

### Silent Payments Scheme

```swift
let privateSign1 = try! P256K.Signing.PrivateKey()
let privateSign2 = try! P256K.Signing.PrivateKey()

let privateKey1 = try! P256K.KeyAgreement.PrivateKey(dataRepresentation: privateSign1.dataRepresentation)
let privateKey2 = try! P256K.KeyAgreement.PrivateKey(dataRepresentation: privateSign2.dataRepresentation)

let sharedSecret1 = try! privateKey1.sharedSecretFromKeyAgreement(with: privateKey2.publicKey)
let sharedSecret2 = try! privateKey2.sharedSecretFromKeyAgreement(with: publicKey1)

let symmetricKey1 = SHA256.hash(data: sharedSecret1.bytes)
let symmetricKey2 = SHA256.hash(data: sharedSecret2.bytes)

let sharedSecretSign1 = try! P256K.Signing.PrivateKey(dataRepresentation: symmetricKey1.bytes)
let sharedSecretSign2 = try! P256K.Signing.PrivateKey(dataRepresentation: symmetricKey2.bytes)

// Spendable Silent Payment private key
let privateTweak1 = try! sharedSecretSign1.add(xonly: privateSign1.publicKey.xonly.bytes)
let publicTweak2 = try! sharedSecretSign2.publicKey.add(privateSign1.publicKey.xonly.bytes)

let schnorrPrivate = try! P256K.Schnorr.PrivateKey(dataRepresentation: sharedSecretSign2.dataRepresentation)
// Payable Silent Payment public key
let xonlyTweak2 = try! schnorrPrivate.xonly.add(privateSign1.publicKey.xonly.bytes)
```

### Recovery

```swift
let privateKey = try! P256K.Recovery.PrivateKey()
let messageData = "We're all Satoshi.".data(using: .utf8)!

// Create a recoverable ECDSA signature
let recoverySignature = try! privateKey.signature(for: messageData)

// Recover an ECDSA public key from a signature
let publicKey = try! P256K.Recovery.PublicKey(messageData, signature: recoverySignature)

// Convert a recoverable signature into a normal signature
let signature = try! recoverySignature.normalize
```

### Combine Public Keys

```swift
let privateKey = try! P256K.Signing.PrivateKey()
let publicKey = try! P256K.Signing.PrivateKey().public

// The Combine API arguments are an array of PublicKey objects and an optional format 
publicKey.combine([privateKey.publicKey], format: .uncompressed)
```

### PEM Key Format

```swift
let privateKeyString = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBXwHPDpec6b07GeLbnwetT0dvWzp0nV3MR+4pPKXIc7oAcGBSuBBAAK
oUQDQgAEt2uDn+2GqqYs/fmkBr5+rCQ3oiFSIJMAcjHIrTDS6HEELgguOatmFBOp
2wU4P2TAl/0Ihiq+nMkrAIV69m2W8g==
-----END EC PRIVATE KEY-----
"""

// Import keys generated from OpenSSL
let privateKey = try! P256K.Signing.PrivateKey(pemRepresentation: privateKeyString)
```

### MuSig2

```swift
// Initialize private keys for two signers
let firstPrivateKey = try P256K.Schnorr.PrivateKey()
let secondPrivateKey = try P256K.Schnorr.PrivateKey()

// Aggregate the public keys using MuSig
let aggregateKey = try P256K.MuSig.aggregate([firstPrivateKey.publicKey, secondPrivateKey.publicKey])

// Message to be signed
let message = "Vires in Numeris.".data(using: .utf8)!
let messageHash = SHA256.hash(data: message)

// Generate nonces for each signer
let firstNonce = try P256K.MuSig.Nonce.generate(
    secretKey: firstPrivateKey,
    publicKey: firstPrivateKey.publicKey,
    msg32: Array(messageHash)
)

let secondNonce = try P256K.MuSig.Nonce.generate(
    secretKey: secondPrivateKey,
    publicKey: secondPrivateKey.publicKey,
    msg32: Array(messageHash)
)

// Aggregate nonces
let aggregateNonce = try P256K.MuSig.Nonce(aggregating: [firstNonce.pubnonce, secondNonce.pubnonce])

// Create partial signatures
let firstPartialSignature = try firstPrivateKey.partialSignature(
    for: messageHash,
    pubnonce: firstNonce.pubnonce,
    secureNonce: firstNonce.secnonce,
    publicNonceAggregate: aggregateNonce,
    publicKeyAggregate: aggregateKey
)

let secondPartialSignature = try secondPrivateKey.partialSignature(
    for: messageHash,
    pubnonce: secondNonce.pubnonce,
    secureNonce: secondNonce.secnonce,
    publicNonceAggregate: aggregateNonce,
    publicKeyAggregate: aggregateKey
)

// Aggregate partial signatures into a full signature
let aggregateSignature = try P256K.MuSig.aggregateSignatures([firstPartialSignature, secondPartialSignature])

// Verify the aggregate signature
let isValid = aggregateKey.isValidSignature(
    firstPartialSignature,
    publicKey: firstPrivateKey.publicKey,
    nonce: firstNonce.pubnonce,
    for: messageHash
)

print("Is valid MuSig signature: \(isValid)")
```

### MuSig2 with External Nonces / Signatures

```swift
// Initialize our own private key and their public key
let hexPrivateKey = "bbb2916c42df478af78e115caac9736d5064070ebaeafc9a230596fd77992eb0".bytes
let boltzServerPublicKeyBytes = "022808ac6b33512a637cf747e650721c0c014acd73e2ded32f1cf90ac7f3b93439".bytes

let boltzServerPublicKey = try! P256K.Schnorr.PublicKey(dataRepresentation: boltzServerPublicKeyBytes, format: .compressed)
let ourPrivateKey = try! P256K.Schnorr.PrivateKey.init(dataRepresentation: hexPrivateKey)

// Boltz swaps pre-date the finalizing of BIP-341 and their sorting is like this; always their own key first, your own key second
let publicKeys = [boltzServerPublicKey, ourPrivateKey.publicKey]
let aggregatedPublicKey = try P256K.MuSig.aggregate(publicKeys, sortKeys: false)

let claimLeafOutputHex = "82012088a914da0da46cf96c2c97093e294b914fbd1948e37ca4882035c61bbbd4a2c348d64d3c060abdce8249d44c09e20b2d8f0c077a5ee7e3dac8ac"
let refundLeafOutputHex = "202808ac6b33512a637cf747e650721c0c014acd73e2ded32f1cf90ac7f3b93439ad029501b1"

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

let lockupTxHex = "01000000000101627ef6f926cb54d199e6c741fcdc2f4dbe0b53072a98a53efd56a713adfc60200100000000ffffffff02668eafb200000000225120dae858cad84658c21ac5b0c72f2cd11cdee3180fcf58776b9a0da12e994a83963bc9000000000000225120e457fe2f36bd6fdc8c35ed82fbff28317939ebb92df6ed338ee82fc71b5a8e7501403bad506b55f875048e7ea99c3a152c3c023e30efddcdedca2c9310e002d26ab4cc17e98bec1fb73f82eb3b34cae0af738a12b6e50f354ae59ed751175675a87300000000"

// Some code beyond the scope of the library to detect the swap output in the lockupTx and calculate the sigHash (which is what has to be signed by both parties)
// Considering I get the same results with Boltz Typescript reference implementation, I think this is fine
let sigHash = "80eec7e830d070c359bcf563ac3262aafb16271ae10dfb97fa45dd8e469ea02b"

let serializedTx = "010000000001012fd6b776e2cdb0e7740a02361eaf26b93feba3f4dd89b5e25cd45a1ef4b31d680100000000fdffffff0173c8000000000000160014b29fab16eafd21afe488f2959afff422eea2a1f401400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

let messageHashBytes = sigHash.bytes
// As this is exactly what we want to sign, we don't SHA256 anything!
let messageDigest = HashDigest(messageHashBytes)

// Generate nonces for each signer
let firstNonce = try P256K.MuSig.Nonce.generate(
    secretKey: ourPrivateKey,
    publicKey: ourPrivateKey.publicKey,
    msg32: Array(messageDigest)
)

let swapID = "MaIfxWHG9o7k"
let ourNonceHex = firstNonce.pubnonce.map { String(format: "%02x", $0) }.joined()
let preimage = "2088479496d83347fd91dda80c074995d18fe7ff001017c3afb73a19b5999d75"

// Create claim request (this is beyond the scope of this library)
let claimRequest = ClaimRequest(
    // it should be safe to leave the index at 0 because we always construct a single-input/single-output transaction
    index: 0,
    transaction: serializedTx,
    preimage: preimage,
    pubNonce: ourNonceHex
)

let claimResponse = try await requestClaimAndProcess(swapID: swapID, claimData: claimRequest)

if let boltzPubNonce = claimResponse.pubNonce, let boltzPartialSignature = claimResponse.partialSignature {
    print("Received Boltz pubNonce: \(boltzPubNonce)")
    print("Received Boltz partialSignature: \(boltzPartialSignature)")
    
    // Convert to P256K objects
    let externalNonce = try P256K.Schnorr.Nonce(hexString: boltzPubNonce)
    let externalPartialSignature = try P256K.Schnorr.PartialSignature(hexString: boltzPartialSignature)
    
    // Aggregate with the external nonce
    let aggregateWithExternal = try P256K.MuSig.Nonce(aggregating: [externalNonce, firstNonce.pubnonce])
    
    print("\n=== NONCES ===")
    print("First Public Nonce: \(firstNonce.hexString)")
    print("External Nonce: \(externalNonce.hexString)")
    print("Aggregate with External: \(aggregateWithExternal.hexString)")
    
    let firstPartialSignature = try ourPrivateKey.partialSignature(
        for: messageDigest,
        pubnonce: firstNonce.pubnonce,
        secureNonce: firstNonce.secnonce,
        publicNonceAggregate: aggregateWithExternal,
        publicKeyAggregate: tweakedAggregatedKey
    )
    
    print("\n=== PARTIAL SIGNATURES ===")
    print("First Partial Signature: \(firstPartialSignature.dataRepresentation.bytes.map { String(format: "%02x", $0) }.joined())")
    print("External Partial Signature: \(externalPartialSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    
    let aggregateSignature = try P256K.MuSig.aggregateSignatures([externalPartialSignature, firstPartialSignature])
    
    let aggregateSignatureHex = aggregateSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined()
    
    print("Aggregate Signature: \(aggregateSignatureHex)")
    
    guard let witness = Data(hexString: aggregateSignatureHex) else {
        print("❌ Failed to parse signature")
        return ClaimResult(success: false, transactionId: nil)
    }
    
    claimTx.setWitness(inputIndex: 0, witness: [witness])
    let finalTx = claimTx.serialize()
    
    print("   Generated Final TX: \(finalTx.hexString)")
    
    let broadcastResponse = try await BoltzAPI.broadcastTransaction(transactionHex: finalTx.hexString)
    
    if let transactionId = broadcastResponse.transactionIdValue {
        print("✅ Transaction broadcasted successfully! TXID: \(transactionId)")
        return ClaimResult(success: true, transactionId: transactionId)
    } else {
        print("❌ Failed to broadcast transaction")
        return ClaimResult(success: false, transactionId: nil)
    }
} else {
    print("Failed to get claim response from Boltz")
    return ClaimResult(success: false, transactionId: nil)
}
```