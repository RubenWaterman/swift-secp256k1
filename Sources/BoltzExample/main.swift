import Foundation
import CryptoKit
import P256K

// MARK: - Extensions

extension String {
    var hexadecimal: [UInt8] {
        var hex = self
        hex.removeAll { $0.isWhitespace }
        var bytes = [UInt8]()
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            let byteString = String(hex[index..<nextIndex])
            if let byte = UInt8(byteString, radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return bytes
    }
}

// MARK: - Boltz API Models

struct BoltzSwapRequest: Codable {
    let invoiceAmount: Int
    let to: String
    let from: String
    let claimPublicKey: String
    let preimageHash: String
}

struct BoltzSwapResponse: Codable {
    let id: String
    let invoice: String
    let swapTree: SwapTree
    let lockupAddress: String
    let refundPublicKey: String
    let timeoutBlockHeight: Int
    let onchainAmount: Int
}

struct SwapTree: Codable {
    let claimLeaf: Leaf
    let refundLeaf: Leaf
}

struct Leaf: Codable {
    let version: Int
    let output: String
}

struct WebSocketMessage: Codable {
    let op: String
    let channel: String
    let args: [String]
}

struct BoltzClaimRequest: Codable {
    let index: Int
    let transaction: String
    let preimage: String
    let pubNonce: String
}

struct BoltzClaimResponse: Codable {
    let partialSignature: String
    let pubNonce: String
}

struct BoltzTransactionRequest: Codable {
    let hex: String
}

struct BoltzRefundResponse: Codable {
    let pubNonce: String
    let partialSignature: String
}

// MARK: - Boltz Client

@available(macOS 12.0, *)
class BoltzClient {
    let endpoint: String
    let webSocketEndpoint: String
    
    init(endpoint: String = "https://api.regtest.getbittr.com") {
        self.endpoint = endpoint
        self.webSocketEndpoint = endpoint.replacingOccurrences(of: "https://", with: "wss://")
    }
    
    func createReverseSwap(request: BoltzSwapRequest) async throws -> BoltzSwapResponse {
        let url = URL(string: "\(endpoint)/v2/swap/reverse")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.httpBody = try JSONEncoder().encode(request)
        
        let (data, response) = try await URLSession.shared.data(for: urlRequest)
        
        // Debug: Print the actual response
        print("📡 HTTP Response Status: \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        print("📡 Raw Response: \(String(data: data, encoding: .utf8) ?? "Unable to decode")")
        
        // Try to decode the response
        do {
            return try JSONDecoder().decode(BoltzSwapResponse.self, from: data)
        } catch {
            print("❌ Decoding error: \(error)")
            
            // Try to parse as a generic dictionary to see the actual structure
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                print("📋 Actual response structure:")
                for (key, value) in json {
                    print("  \(key): \(value)")
                }
            }
            
            throw error
        }
    }
    
    func claimSwap(swapId: String, request: BoltzClaimRequest) async throws -> BoltzClaimResponse {
        let url = URL(string: "\(endpoint)/v2/swap/reverse/\(swapId)/claim")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.httpBody = try JSONEncoder().encode(request)
        
        let (data, response) = try await URLSession.shared.data(for: urlRequest)
        
        print("📡 Claim Response Status: \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        print("📡 Claim Raw Response: \(String(data: data, encoding: .utf8) ?? "Unable to decode")")
        
        return try JSONDecoder().decode(BoltzClaimResponse.self, from: data)
    }
    
    func broadcastTransaction(request: BoltzTransactionRequest) async throws {
        let url = URL(string: "\(endpoint)/v2/chain/BTC/transaction")!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.httpBody = try JSONEncoder().encode(request)
        
        let (data, response) = try await URLSession.shared.data(for: urlRequest)
        
        print("📡 Broadcast Response Status: \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        print("📡 Broadcast Raw Response: \(String(data: data, encoding: .utf8) ?? "Unable to decode")")
    }
}

// MARK: - WebSocket Connection
@available(macOS 12.0, *)
class BoltzWebSocket {
    private var webSocket: URLSessionWebSocketTask?
    private let url: URL
    private let swapId: String
    private let client: BoltzClient
    private let privateKey: P256K.Schnorr.PrivateKey
    private let preimage: [UInt8]
    private let destinationAddress: String
    
    init(swapId: String, client: BoltzClient, privateKey: P256K.Schnorr.PrivateKey, preimage: [UInt8], destinationAddress: String) {
        self.swapId = swapId
        self.client = client
        self.privateKey = privateKey
        self.preimage = preimage
        self.destinationAddress = destinationAddress
        self.url = URL(string: "wss://api.regtest.getbittr.com/v2/ws")!
    }
    
    func connect() {
        let session = URLSession(configuration: .default)
        webSocket = session.webSocketTask(with: url)
        webSocket?.resume()
        
        // Send subscription message
        let subscribeMessage = [
            "op": "subscribe",
            "channel": "swap.update",
            "args": [swapId]
        ] as [String : Any]
        
        if let data = try? JSONSerialization.data(withJSONObject: subscribeMessage),
           let message = String(data: data, encoding: .utf8) {
            webSocket?.send(.string(message)) { [weak self] error in
                if let error = error {
                    print("Failed to send subscription: \(error)")
                } else {
                    print("Subscribed to swap updates for ID: \(self?.swapId ?? "unknown")")
                }
            }
        }
        
        receiveMessage()
    }
    
    private func receiveMessage() {
        webSocket?.receive { [weak self] result in
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self?.handleMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self?.handleMessage(text)
                    }
                @unknown default:
                    break
                }
                // Continue receiving messages
                self?.receiveMessage()
                
            case .failure(let error):
                print("WebSocket receive error: \(error)")
            }
        }
    }
    
    private func handleMessage(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            print("Failed to parse WebSocket message")
            return
        }
        
        print("Got WebSocket update:")
        print(json)
        print()
        
        guard let event = json["event"] as? String,
              event == "update",
              let args = json["args"] as? [[String: Any]],
              let firstArg = args.first,
              let status = firstArg["status"] as? String else {
            return
        }
        
        switch status {
        case "swap.created":
            print("Waiting for invoice to be paid")
            
        case "transaction.mempool":
            print("Creating claim transaction")
            
            // Extract transaction data from the message
            guard let transactionData = firstArg["transaction"] as? [String: Any],
                  let transactionHex = transactionData["hex"] as? String else {
                print("❌ No transaction hex found in mempool message")
                return
            }
            
            print("📋 Lockup transaction hex: \(transactionHex)")
            
            // TODO: Implement the full claim logic
            // For now, let's just print what we need to do
            print("🔧 Claim transaction steps needed:")
            print("1. Parse the lockup transaction")
            print("2. Find the swap output")
            print("3. Create a MuSig2 session")
            print("4. Create claim transaction")
            print("5. Get partial signature from Boltz")
            print("6. Sign and broadcast")
            
            // For development, let's try to get a partial signature from Boltz
            // This will help us understand the API structure
            Task {
                await attemptClaimTransaction(swapId: swapId, transactionHex: transactionHex, privateKey: privateKey, preimage: preimage)
            }
            
        case "invoice.settled":
            print("Swap successful")
            webSocket?.cancel()
            
        default:
            print("Unknown status: \(status)")
        }
    }
    
    func disconnect() {
        webSocket?.cancel()
    }
    
    private func attemptClaimTransaction(swapId: String, transactionHex: String, privateKey: P256K.Schnorr.PrivateKey, preimage: [UInt8]) async {
        print("🔧 Attempting to claim transaction")
        
        do {
            // Convert our Signing.PublicKey to Schnorr.PublicKey for MuSig aggregation
            let ourPublicKey = privateKey.publicKey
            let ourSchnorrPublicKey = try! P256K.Schnorr.PublicKey(
                dataRepresentation: ourPublicKey.dataRepresentation,
                format: .compressed
            )
            
            let boltzServerPublicKeyBytes = "0241378915c3302c44989fcb499c8e98b4e8da259062bbcb698bc043a7795b4ce6".hexadecimal
        
            let boltzServerPublicKey = try! P256K.Schnorr.PublicKey(
                dataRepresentation: Data(boltzServerPublicKeyBytes),
                format: .compressed
            )
            
            print("Boltz server public key: \(boltzServerPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
            print("Our Schnorr public key: \(ourSchnorrPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

            let boltzAggregateKey = try P256K.MuSig.aggregate([boltzServerPublicKey, ourSchnorrPublicKey], sortKeys: false)
            
            print("Aggregate key: \(boltzAggregateKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

            // Step 1: Create a simple claim transaction hex (placeholder)
            // In a real implementation, this would be a proper Bitcoin transaction
            let placeholderClaimTx = "02000000000000000000" // Placeholder hex
            
            // Step 2: Generate a public nonce for MuSig2
            // For now, we'll use a placeholder
            let placeholderPubNonce = "placeholder_pubnonce"
            
            // Step 3: Create claim request
            let claimRequest = BoltzClaimRequest(
                index: 0,
                transaction: placeholderClaimTx,
                preimage: preimage.map { String(format: "%02x", $0) }.joined(),
                pubNonce: placeholderPubNonce
            )
            
            print("📋 Sending claim request to Boltz...")
            let claimResponse = try await client.claimSwap(swapId: swapId, request: claimRequest)
            
            print("✅ Received claim response:")
            print("  Partial signature: \(claimResponse.partialSignature)")
            print("  Public nonce: \(claimResponse.pubNonce)")
            
        } catch {
            print("❌ Error attempting claim: \(error)")
        }
    }
}

// MARK: - Simple Boltz Example

@available(macOS 12.0, *)
class SimpleBoltzExample {
    private let client = BoltzClient()
    private let invoiceAmount = 50_000
    private let destinationAddress = "bcrt1q86yrllp6mzcdxpvgm8rap7cwwpfnrrgvujsqd0"
    
    // Hardcoded private key for development (32 bytes)
    // This allows us to reuse the same key and avoid paying invoices repeatedly
    private let hardcodedPrivateKeyHex = "f1709ec6ca1e8f06508a3d2c23b7503b6457c1fe60ecac46ab0ebf4082a2c640"
    
    // Hardcoded preimage for development (32 bytes)
    private let hardcodedPreimageBytes: [UInt8] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    ]
    
    func runExample() async {
        do {
            print("🚀 Starting Boltz Claim Example (Skipping Swap Creation)")
            print("=====================================================")
            
            // Use hardcoded preimage for development
            let preimage = hardcodedPreimageBytes
            let preimageHash = Array(SHA256.hash(data: Data(preimage)))
            
            print("\n📋 Using hardcoded preimage and hash")
            print("Preimage: \(preimage.map { String(format: "%02x", $0) }.joined())")
            print("Preimage hash: \(preimageHash.map { String(format: "%02x", $0) }.joined())")
            
            // Use hardcoded P256K Signing key pair
            let privateKeyBytes = hardcodedPrivateKeyHex.hexadecimal
            let privateKey = try P256K.Schnorr.PrivateKey(dataRepresentation: Data(privateKeyBytes))
            let ourPublicKey = privateKey.publicKey

            // Get the compressed public key format (33 bytes starting with 02/03)
            let compressedPublicKey = ourPublicKey.dataRepresentation
            
            print("\n📋 Using hardcoded P256K Signing key pair")
            print("Private key: \(hardcodedPrivateKeyHex)")
            print("Public key (compressed): \(compressedPublicKey.map { String(format: "%02x", $0) }.joined())")
            print("Public key length: \(compressedPublicKey.count) bytes")
            print("Public key format: \(ourPublicKey.format)")
            print("First byte: \(String(format: "%02x", compressedPublicKey.first ?? 0))")
            
            // Convert to Schnorr format for MuSig
            let boltzServerPublicKeyBytes = "0241378915c3302c44989fcb499c8e98b4e8da259062bbcb698bc043a7795b4ce6".hexadecimal
        
            let boltzServerPublicKey = try! P256K.Schnorr.PublicKey(
                dataRepresentation: Data(boltzServerPublicKeyBytes),
                format: .compressed
            )
            
            // Convert our Signing.PublicKey to Schnorr.PublicKey for MuSig aggregation
            let ourSchnorrPublicKey = try! P256K.Schnorr.PublicKey(
                dataRepresentation: ourPublicKey.dataRepresentation,
                format: .compressed
            )
            
            print("Boltz server public key: \(boltzServerPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
            print("Our Schnorr public key: \(ourSchnorrPublicKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")

            let boltzAggregateKey = try P256K.MuSig.aggregate([boltzServerPublicKey, ourSchnorrPublicKey], sortKeys: false)
            
            print("Aggregate key: \(boltzAggregateKey.dataRepresentation.map { String(format: "%02x", $0) }.joined())")
            
            let tweak = try! "82012088a914772e71cb02fdf4430127ba1239539dd7e2375a838820f8b2dfc86aa1f5c6df0d3089c74088eaf0527216b61472113e8839e4e4bbb69fac".hexadecimal
            let tweakedKey = try! boltzAggregateKey.add(Data(tweak))
            
            let hexTweakedString = tweakedKey.dataRepresentation.map { String(format: "%02x", $0) }.joined()
            print("hexTweakedString: \(hexTweakedString)")
            
            // Message to be signed
            let message = "Vires in Numeris.".data(using: .utf8)!
            let messageHash = SHA256.hash(data: message)

            // Generate nonces for each signer
            let firstNonce = try P256K.MuSig.Nonce.generate(
                secretKey: privateKey,
                publicKey: ourSchnorrPublicKey,
                msg32: Array(messageHash)
            )
            
            print("firstNonce: \(firstNonce.hexString)")
            
            // Make API call to get refund partial signature from Boltz
            let refundEndpoint = "https://api.regtest.getbittr.com/v2/swap/submarine/\(swapId)/refund"
            
            let requestBody: [String: Any] = [
                "pubNonce": firstNonce.hexString,
                "transaction": "placeholder_transaction_hex", // We'll use a placeholder for now
                "index": 0
            ]
            
            print("📡 Making refund API call to: \(refundEndpoint)")
            print("📡 Request body: \(requestBody)")
            
            // add some code here to build the transaction
            
            // Use existing swap data from the successful run
            let existingSwapId = "JBNzhT7v2vcW"
            let existingRefundPublicKey = "0241378915c3302c44989fcb499c8e98b4e8da259062bbcb698bc043a7795b4ce6"
            let existingLockupTxHex = "01000000000101f4ae8e1a2b9593587c473ca9da0f3d4509a11be2e8f4f59915267de3993d6c910100000000ffffffff02949bcfb20000000022512011bf1b0748b8ada4f0c36e656a155e629ff3050188d079fbbf03a5a3745cb3bc22c10000000000002251207e9a56588de2436ecde36daacfa09c0d16859cbec9610f19730440347fb0fc71024730440220770ad26954e5e00ab339c84e5d18e63f9bf87453d03b6c7dd16d0df41b81a0e602203336c8f4822791ca5daafd5909efb9c1c4c994beda659648569bb0cecff314b0012103e38ad4d38825dcb29763e9b76bc4136cc6c751efd89f120346aae5fee8f2dd8e00000000"
            
            print("\n📋 Using existing swap data")
            print("Swap ID: \(existingSwapId)")
            print("Refund public key: \(existingRefundPublicKey)")
            print("Lockup transaction: \(existingLockupTxHex)")
            
            // Start the claim process directly
            print("\n🔧 Starting claim process...")
            await attemptClaimTransaction(swapId: existingSwapId, transactionHex: existingLockupTxHex, privateKey: privateKey, preimage: preimage)
            
            print("\n🎉 Claim example completed!")
            print("=====================================================")
            
        } catch {
            print("❌ Error: \(error)")
        }
    }
    
    private func generateRandomBytes(count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }
}

// MARK: - Main Execution

@main
struct BoltzExampleApp {
    static func main() async {
        if #available(macOS 12.0, *) {
            let example = SimpleBoltzExample()
            await example.runExample()
        } else {
            print("❌ This example requires macOS 12.0 or newer")
        }
    }
} 
