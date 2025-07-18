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

#if canImport(libsecp256k1_zkp)
    @_implementationOnly import libsecp256k1_zkp
#elseif canImport(libsecp256k1)
    @_implementationOnly import libsecp256k1
#endif

public extension P256K.MuSig {
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
        public init(aggregating pubnonces: [P256K.Schnorr.Nonce]) throws {
            let context = P256K.Context.rawRepresentation
            var aggNonce = secp256k1_musig_aggnonce()

            // Parse the serialized nonces back into internal structures
            let parsedNonces = try pubnonces.map { schnorrNonce in
                var pubnonce = secp256k1_musig_pubnonce()
                // Parse the serialized 66-byte data back into the internal structure
                guard schnorrNonce.pubnonce.withUnsafeBytes({ bytes in
                    secp256k1_musig_pubnonce_parse(context, &pubnonce, bytes.baseAddress!).boolValue
                }) else {
                    throw secp256k1Error.underlyingCryptoError
                }
                return pubnonce
            }

            guard PointerArrayUtility.withUnsafePointerArray(
                parsedNonces, { pointers in
                    secp256k1_musig_nonce_agg(context, &aggNonce, pointers, pointers.count).boolValue
                }
            ) else {
                throw secp256k1Error.underlyingCryptoError
            }

            self.aggregatedNonce = Data(Swift.withUnsafeBytes(of: aggNonce) { Data($0) })
        }

        /// Provides access to the raw bytes of the aggregated nonce.
        ///
        /// - Parameter body: A closure that takes an `UnsafeRawBufferPointer` and returns a value.
        /// - Returns: The value returned by the closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try aggregatedNonce.withUnsafeBytes(body)
        }

        /// Returns an iterator over the bytes of the aggregated nonce.
        ///
        /// - Returns: An iterator for the aggregated nonce data.
        public func makeIterator() -> Data.Iterator {
            aggregatedNonce.makeIterator()
        }

        /// A hex string representation of the aggregated nonce.
        public var hexString: String {
            aggregatedNonce.hexString
        }

        /// Parses a serialized public nonce from hex string format.
        ///
        /// This function takes a hex string representing a 66-byte serialized public nonce
        /// and converts it to a MuSig nonce that can be used for aggregation.
        /// Uses the underlying secp256k1_musig_pubnonce_parse function for proper validation.
        ///
        /// - Parameter hexString: A hex string representing the 66-byte serialized public nonce.
        /// - Returns: A `P256K.Schnorr.Nonce` that can be used for MuSig operations.
        /// - Throws: An error if the hex string is invalid or parsing fails.
        public static func parse(hexString: String) throws -> P256K.Schnorr.Nonce {
            let data = try Data(hexString: hexString)
            return try parse(data: data)
        }

        /// Parses a serialized public nonce from raw data.
        ///
        /// This function takes raw data representing a 66-byte serialized public nonce
        /// and converts it to a MuSig nonce that can be used for aggregation.
        /// Uses the underlying secp256k1_musig_pubnonce_parse function for proper validation.
        ///
        /// - Parameter data: Raw data representing the 66-byte serialized public nonce.
        /// - Returns: A `P256K.Schnorr.Nonce` that can be used for MuSig operations.
        /// - Throws: An error if the data is invalid or parsing fails.
        public static func parse(data: Data) throws -> P256K.Schnorr.Nonce {
            let context = P256K.Context.rawRepresentation
            var pubnonce = secp256k1_musig_pubnonce()
            
            // Parse the serialized data using the underlying C function
            guard data.withUnsafeBytes({ bytes in
                secp256k1_musig_pubnonce_parse(context, &pubnonce, bytes.baseAddress!).boolValue
            }) else {
                throw secp256k1Error.underlyingCryptoError
            }
            
            // Serialize back to the standard 66-byte format
            var serializedPubnonce = [UInt8](repeating: 0, count: 66)
            guard serializedPubnonce.withUnsafeMutableBufferPointer({ buffer in
                secp256k1_musig_pubnonce_serialize(context, buffer.baseAddress!, &pubnonce).boolValue
            }) else {
                throw secp256k1Error.underlyingCryptoError
            }
            
            return try P256K.Schnorr.Nonce(data: Data(serializedPubnonce))
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
            secretKey: P256K.Schnorr.PrivateKey?,
            publicKey: P256K.Schnorr.PublicKey,
            msg32: [UInt8],
            extraInput32: [UInt8]? = nil
        ) throws -> NonceResult {
            try generate(
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
            secretKey: P256K.Schnorr.PrivateKey?,
            publicKey: P256K.Schnorr.PublicKey,
            msg32: [UInt8],
            extraInput32: [UInt8]?
        ) throws -> NonceResult {
            let context = P256K.Context.rawRepresentation
            var secnonce = secp256k1_musig_secnonce()
            var pubnonce = secp256k1_musig_pubnonce()
            var pubkey = publicKey.baseKey.rawRepresentation

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

            // Serialize the public nonce to the proper 66-byte format
            var serializedPubnonce = [UInt8](repeating: 0, count: 66)
            guard serializedPubnonce.withUnsafeMutableBufferPointer({ buffer in
                secp256k1_musig_pubnonce_serialize(context, buffer.baseAddress!, &pubnonce).boolValue
            }) else {
                throw secp256k1Error.underlyingCryptoError
            }

            return NonceResult(
                pubnonce: try P256K.Schnorr.Nonce(data: Data(serializedPubnonce)),
                secnonce: P256K.Schnorr.SecureNonce(Swift.withUnsafeBytes(of: secnonce) { Data($0) })
            )
        }
    }

    /// Represents the result of nonce generation, containing both public and secret nonces.
    @frozen struct NonceResult: ~Copyable {
        /// The public nonce.
        public let pubnonce: P256K.Schnorr.Nonce
        /// The secret nonce.
        public let secnonce: P256K.Schnorr.SecureNonce
        
        /// A hex string representation of the public nonce.
        public var hexString: String {
            pubnonce.hexString
        }
    }
}

public extension P256K.Schnorr {
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

        /// Creates a public nonce from raw data.
        ///
        /// - Parameter data: The 66-byte public nonce data.
        /// - Throws: An error if the data is not exactly 66 bytes.
        public init(data: Data) throws {
            guard data.count == 66 else {
                throw secp256k1Error.underlyingCryptoError
            }
            self.pubnonce = data
        }

        /// Creates a public nonce from a hex string.
        ///
        /// - Parameter hexString: A hex string representing the 66-byte public nonce.
        /// - Throws: An error if the hex string is invalid or not exactly 132 characters (66 bytes).
        public init(hexString: String) throws {
            guard hexString.count == 132 else { // 66 bytes = 132 hex characters
                throw secp256k1Error.underlyingCryptoError
            }
            let data = try Data(hexString: hexString)
            guard data.count == 66 else {
                throw secp256k1Error.underlyingCryptoError
            }
            self.pubnonce = data
        }

        /// Provides access to the raw bytes of the public nonce.
        ///
        /// - Parameter body: A closure that takes an `UnsafeRawBufferPointer` and returns a value.
        /// - Returns: The value returned by the closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try pubnonce.withUnsafeBytes(body)
        }

        /// Returns an iterator over the bytes of the public nonce.
        ///
        /// - Returns: An iterator for the public nonce data.
        public func makeIterator() -> Data.Iterator {
            pubnonce.makeIterator()
        }

        /// A hex string representation of the public nonce.
        public var hexString: String {
            pubnonce.hexString
        }
    }
}