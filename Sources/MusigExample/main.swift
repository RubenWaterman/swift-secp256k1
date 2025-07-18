import Foundation
import P256K

// Example of MuSig multi-signature scheme
func runMusigExample() throws {
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

    // Verify the aggregate signature using the xonly public key
    let schnorrSignature = try P256K.Schnorr.SchnorrSignature(dataRepresentation: aggregateSignature.dataRepresentation)
    let schnorrXonlyKey = P256K.Schnorr.XonlyKey(dataRepresentation: aggregateKey.xonly.bytes)
    let isValid = schnorrXonlyKey.isValidSignature(schnorrSignature, for: messageHash)

    // Print hexadecimal representations
    print("Aggregated Public Key (hex): \(Data(aggregateKey.xonly.bytes).map { String(format: "%02x", $0) }.joined())")
    print("Message Hash (hex): \(Data(messageHash).map { String(format: "%02x", $0) }.joined())")
    print("Aggregate Signature (hex): \(aggregateSignature.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
    print("Is valid MuSig signature: \(isValid)")
}

// Run the example
do {
    try runMusigExample()
} catch {
    print("Error: \(error)")
}