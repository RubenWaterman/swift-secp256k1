//
//  Nonces.swift
//  21-DOT-DEV/swift-secp256k1
//
//  Copyright (c) 2024 GigaBitcoin LLC
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation

public extension secp256k1.MuSig {
    /// Represents an aggregated nonce for MuSig operations.
    ///
    /// This struct is used in the MuSig multi-signature scheme to handle nonce aggregation.
    struct Nonce: ContiguousBytes, Sequence {
        /// The aggregated nonce data.
        let aggregatedNonce: Data

        /// Creates an aggregated nonce from multiple public nonces.
        ///
        /// - Parameter pubnonces: An array of public nonces to aggregate.
        /// - Throws: An error if nonce aggregation fails.
        public init(aggregating pubnonces: [secp256k1.Schnorr.Nonce]) throws {
            let context = secp256k1.Context.rawRepresentation
            var aggNonce = secp256k1_musig_aggnonce()

            guard PointerArrayUtility.withUnsafePointerArray(
                pubnonces.map {
                    var pubnonce = secp256k1_musig_pubnonce()
                    $0.pubnonce.copyToUnsafeMutableBytes(of: &pubnonce.data)
                    return pubnonce
                }, { pointers in
                    secp256k1_musig_nonce_agg(context, &aggNonce, pointers, pointers.count).boolValue
                }) else {
                throw secp256k1Error.underlyingCryptoError
            }

            self.aggregatedNonce = Data(Swift.withUnsafeBytes(of: aggNonce) { Data($0) })
        }

        /// Provides access to the raw bytes of the aggregated nonce.
        ///
        /// - Parameter body: A closure that takes an `UnsafeRawBufferPointer` and returns a value.
        /// - Returns: The value returned by the closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try aggregatedNonce.withUnsafeBytes(body)
        }

        /// Returns an iterator over the bytes of the aggregated nonce.
        ///
        /// - Returns: An iterator for the aggregated nonce data.
        public func makeIterator() -> Data.Iterator {
            return aggregatedNonce.makeIterator()
        }

        /// Generates a nonce pair (secret and public) for MuSig signing.
        ///
        /// This function implements the nonce generation process as described in BIP-327.
        /// It is crucial to use a unique `sessionID` for each signing session to prevent nonce reuse.
        ///
        /// - Parameters:
        ///   - secretKey: The signer's secret key (optional).
        ///   - publicKey: The signer's public key.
        ///   - msg32: The 32-byte message to be signed.
        ///   - extraInput32: Optional 32-byte extra input to customize the nonce (can be nil).
        /// - Returns: A `NonceResult` containing the generated public and secret nonces.
        /// - Throws: An error if nonce generation fails.
        public static func generate(
            secretKey: secp256k1.Schnorr.PrivateKey?,
            publicKey: secp256k1.Schnorr.PublicKey,
            msg32: [UInt8],
            extraInput32: [UInt8]? = nil
        ) throws -> NonceResult {
            try Self.generate(
                sessionID: Array(SecureBytes(count: 133)),
                secretKey: secretKey,
                publicKey: publicKey,
                msg32: msg32,
                extraInput32: extraInput32
            )
        }

        /// Generates a nonce pair (secret and public) for MuSig signing.
        ///
        /// This function implements the nonce generation process as described in BIP-327.
        /// It is crucial to use a unique `sessionID` for each signing session to prevent nonce reuse.
        ///
        /// - Parameters:
        ///   - sessionID: A 32-byte unique session identifier.
        ///   - secretKey: The signer's secret key (optional).
        ///   - publicKey: The signer's public key.
        ///   - msg32: The 32-byte message to be signed.
        ///   - extraInput32: Optional 32-byte extra input to customize the nonce (can be nil).
        /// - Returns: A `NonceResult` containing the generated public and secret nonces.
        /// - Throws: An error if nonce generation fails.
        public static func generate(
            sessionID: [UInt8],
            secretKey: secp256k1.Schnorr.PrivateKey?,
            publicKey: secp256k1.Schnorr.PublicKey,
            msg32: [UInt8],
            extraInput32: [UInt8]?
        ) throws -> NonceResult {
            let context = secp256k1.Context.rawRepresentation
            var secnonce = secp256k1_musig_secnonce()
            var pubnonce = secp256k1_musig_pubnonce()
            var pubkey = publicKey.rawRepresentation

#if canImport(zkp_bindings)
            guard secp256k1_musig_nonce_gen(
                context,
                &secnonce,
                &pubnonce,
                sessionID,
                Array(secretKey!.dataRepresentation),
                &pubkey,
                msg32,
                nil,
                extraInput32
            ).boolValue else {
                throw secp256k1Error.underlyingCryptoError
            }
#else
            var mutableSessionID = sessionID

            guard secp256k1_musig_nonce_gen(
                context,
                &secnonce,
                &pubnonce,
                &mutableSessionID,
                Array(secretKey!.dataRepresentation),
                &pubkey,
                msg32,
                nil,
                extraInput32
            ).boolValue else {
                throw secp256k1Error.underlyingCryptoError
            }
#endif

            return NonceResult(
                pubnonce: secp256k1.Schnorr.Nonce(pubnonce: Swift.withUnsafeBytes(of: pubnonce) { Data($0) }),
                secnonce: secp256k1.Schnorr.SecureNonce(Swift.withUnsafeBytes(of: secnonce) { Data($0) })
            )
        }
    }

    /// Represents the result of nonce generation, containing both public and secret nonces.
    @frozen struct NonceResult: ~Copyable {
        /// The public nonce.
        public let pubnonce: secp256k1.Schnorr.Nonce
        /// The secret nonce.
        public let secnonce: secp256k1.Schnorr.SecureNonce
    }
}

public extension secp256k1.Schnorr {
    /// Represents a secure nonce used for MuSig operations.
    ///
    /// This struct is used to handle secure nonces in the MuSig signing process.
    /// It's crucial not to reuse nonces across different signing sessions to maintain security.
    struct SecureNonce: ~Copyable {
        let data: Data

        init(_ data: Data) {
            self.data = data
        }
    }

    /// Represents a public nonce used for MuSig operations.
    struct Nonce: ContiguousBytes, Sequence {
        /// The public nonce data.
        let pubnonce: Data
        
        /// Creates a public nonce from serialized 66-byte data.
        ///
        /// This initializer parses a serialized public nonce using the secp256k1_musig_pubnonce_parse function.
        /// The input must be a 66-byte array representing the compressed form of two public keys.
        ///
        /// - Parameter serializedNonce: A 66-byte serialized nonce.
        /// - Throws: An error if parsing fails.
        public init(serializedNonce: Data) throws {
            guard serializedNonce.count == 66 else {
                throw secp256k1Error.incorrectParameterSize
            }
            
            let context = secp256k1.Context.rawRepresentation
            var pubnonce = secp256k1_musig_pubnonce()
            
            var serializedCopy = [UInt8](serializedNonce)
            guard serializedCopy.withUnsafeMutableBytes({ serializedPtr in
                secp256k1_musig_pubnonce_parse(context, &pubnonce, serializedPtr.baseAddress!).boolValue
            }) else {
                throw secp256k1Error.underlyingCryptoError
            }
            
            self.pubnonce = Data(Swift.withUnsafeBytes(of: pubnonce) { Data($0) })
        }
        
        /// Creates a public nonce from serialized 66-byte array.
        ///
        /// This initializer parses a serialized public nonce using the secp256k1_musig_pubnonce_parse function.
        /// The input must be a 66-byte array representing the compressed form of two public keys.
        ///
        /// - Parameter serializedNonce: A 66-byte serialized nonce array.
        /// - Throws: An error if parsing fails.
        public init(serializedNonce: [UInt8]) throws {
            try self.init(serializedNonce: Data(serializedNonce))
        }
        
        /// Creates a public nonce from a hexadecimal string representation.
        ///
        /// This initializer parses a serialized public nonce from a hexadecimal string.
        /// The input string must represent 66 bytes (132 hex characters) of data.
        ///
        /// - Parameter hexString: A hexadecimal string representing the 66-byte serialized nonce.
        /// - Throws: An error if parsing fails or the string is not valid hex.
        public init(hexString: String) throws {
            // Remove any "0x" prefix if present
            var cleanedHexString = hexString
            if hexString.hasPrefix("0x") {
                cleanedHexString = String(hexString.dropFirst(2))
            }
            
            // Check if the hex string has the correct length
            guard cleanedHexString.count == 132 else {
                throw secp256k1Error.incorrectParameterSize
            }
            
            // Convert hex string to bytes
            var bytes = [UInt8]()
            bytes.reserveCapacity(66)
            
            var index = cleanedHexString.startIndex
            while index < cleanedHexString.endIndex {
                let nextIndex = cleanedHexString.index(index, offsetBy: 2)
                let byteString = cleanedHexString[index..<nextIndex]
                
                guard let byte = UInt8(byteString, radix: 16) else {
                    throw secp256k1Error.invalidPublicKey
                }
                
                bytes.append(byte)
                index = nextIndex
            }
            
            try self.init(serializedNonce: bytes)
        }

        /// Initializes a nonce with pre-parsed pubnonce data.
        ///
        /// - Parameter pubnonce: The raw pubnonce data.
        init(pubnonce: Data) {
            self.pubnonce = pubnonce
        }

        /// Provides access to the raw bytes of the public nonce.
        ///
        /// - Parameter body: A closure that takes an `UnsafeRawBufferPointer` and returns a value.
        /// - Returns: The value returned by the closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try pubnonce.withUnsafeBytes(body)
        }

        /// Returns an iterator over the bytes of the public nonce.
        ///
        /// - Returns: An iterator for the public nonce data.
        public func makeIterator() -> Data.Iterator {
            return pubnonce.makeIterator()
        }

        /// Serializes the public nonce to a 66-byte representation.
        ///
        /// This method serializes the internal nonce representation to a 66-byte array
        /// that can be shared with other parties in the MuSig protocol.
        ///
        /// - Returns: A 66-byte Data object containing the serialized nonce.
        /// - Throws: An error if serialization fails.
        public func serialized() throws -> Data {
            let context = secp256k1.Context.rawRepresentation
            var output = Data(count: 66)
            var nonceCopy = secp256k1_musig_pubnonce()
            
            pubnonce.copyToUnsafeMutableBytes(of: &nonceCopy.data)
            
            guard output.withUnsafeMutableBytes({ outputPtr in
                secp256k1_musig_pubnonce_serialize(context, outputPtr.baseAddress!, &nonceCopy).boolValue
            }) else {
                throw secp256k1Error.underlyingCryptoError
            }
            
            return output
        }

        /// Serializes the public nonce to a hexadecimal string representation.
        ///
        /// This method serializes the internal nonce representation to a 132-character
        /// hexadecimal string that can be shared with other parties in the MuSig protocol.
        ///
        /// - Parameter uppercase: Whether to use uppercase letters in the hex string. Default is false.
        /// - Returns: A 132-character hexadecimal string containing the serialized nonce.
        /// - Throws: An error if serialization fails.
        public func serializedHex(uppercase: Bool = false) throws -> String {
            let data = try serialized()
            var hexString = ""
            for byte in data {
                hexString += String(format: uppercase ? "%02X" : "%02x", byte)
            }
            return hexString
        }
    }
}
