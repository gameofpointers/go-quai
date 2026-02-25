import Foundation

/// Swift wrapper around the Go libquaiwallet C FFI.
/// All Go functions accept/return JSON via C strings.
class QuaiWallet {

    let walletId: String

    /// Create a wallet from an existing mnemonic phrase.
    init(phrase: String, password: String = "", coinType: UInt32 = 994) throws {
        let input: [String: Any] = [
            "phrase": phrase,
            "password": password,
            "coinType": coinType
        ]
        let result = try Self.callFFI(Self.jsonString(input), CreateWalletFromPhrase)
        guard let id = result["walletId"] as? String else {
            throw WalletError.invalidResponse("missing walletId")
        }
        self.walletId = id
    }

    /// Create a wallet with a new random mnemonic.
    static func createRandom(coinType: UInt32 = 994) throws -> (wallet: QuaiWallet, phrase: String) {
        let input: [String: Any] = ["coinType": coinType]
        let result = try callFFI(jsonString(input), CreateRandomWallet)
        guard let id = result["walletId"] as? String,
              let phrase = result["phrase"] as? String else {
            throw WalletError.invalidResponse("missing walletId or phrase")
        }
        let wallet = QuaiWallet(id: id)
        return (wallet, phrase)
    }

    private init(id: String) {
        self.walletId = id
    }

    deinit {
        let cId = walletId.cString(using: .utf8)!
        cId.withUnsafeBufferPointer { buf in
            DestroyWallet(UnsafeMutablePointer(mutating: buf.baseAddress!))
        }
    }

    // MARK: - Address Derivation

    struct AddressInfo {
        let pubKey: String
        let address: String
        let account: UInt32
        let index: UInt32
        let zone: [UInt8]
        let isQi: Bool
    }

    /// Derive the next address for a given account and zone.
    func deriveAddress(account: UInt32 = 0, zone: [UInt8] = [0, 0]) throws -> AddressInfo {
        let input: [String: Any] = [
            "walletId": walletId,
            "account": account,
            "zone": zone
        ]
        let result = try Self.callFFI(Self.jsonString(input), DeriveAddress)
        return try Self.parseAddressInfo(result)
    }

    /// Get the private key for a previously derived address.
    func getPrivateKey(address: String) throws -> String {
        let input: [String: Any] = [
            "walletId": walletId,
            "address": address
        ]
        let result = try Self.callFFI(Self.jsonString(input), GetPrivateKey)
        guard let key = result["privateKey"] as? String else {
            throw WalletError.invalidResponse("missing privateKey")
        }
        return key
    }

    // MARK: - Transaction Signing

    /// Sign a Quai (account-based) transaction.
    func signQuaiTransaction(
        address: String,
        chainId: Int64,
        nonce: UInt64,
        gasPrice: String,
        gas: UInt64,
        to: String,
        value: String,
        data: String = "",
        zone: [UInt8] = [0, 0]
    ) throws -> String {
        let input: [String: Any] = [
            "walletId": walletId,
            "address": address,
            "chainId": chainId,
            "nonce": nonce,
            "gasPrice": gasPrice,
            "gas": gas,
            "to": to,
            "value": value,
            "data": data,
            "zone": zone
        ]
        let result = try Self.callFFI(Self.jsonString(input), SignQuaiTransaction)
        guard let txHex = result["txHex"] as? String else {
            throw WalletError.invalidResponse("missing txHex")
        }
        return txHex
    }

    // MARK: - Serialization

    /// Serialize wallet state to JSON string for storage.
    func serialize() throws -> String {
        let input: [String: Any] = ["walletId": walletId]
        let jsonStr = Self.jsonString(input)

        let cInput = jsonStr.cString(using: .utf8)!
        let cResult = cInput.withUnsafeBufferPointer { buf in
            SerializeWallet(UnsafeMutablePointer(mutating: buf.baseAddress!))
        }
        defer { FreeString(cResult) }

        guard let result = cResult else {
            throw WalletError.nullResponse
        }
        return String(cString: result)
    }

    /// Restore a wallet from serialized JSON state.
    static func deserialize(_ json: String) throws -> QuaiWallet {
        let cInput = json.cString(using: .utf8)!
        let cResult = cInput.withUnsafeBufferPointer { buf in
            DeserializeWalletFromJSON(UnsafeMutablePointer(mutating: buf.baseAddress!))
        }
        defer { FreeString(cResult) }

        guard let result = cResult else {
            throw WalletError.nullResponse
        }
        let dict = try Self.parseJSON(String(cString: result))
        guard let id = dict["walletId"] as? String else {
            throw WalletError.invalidResponse("missing walletId")
        }
        return QuaiWallet(id: id)
    }

    // MARK: - Validation

    /// Check if a mnemonic phrase is valid.
    static func isValidMnemonic(_ phrase: String) -> Bool {
        let input: [String: Any] = ["phrase": phrase]
        guard let result = try? callFFI(jsonString(input), ValidateMnemonic),
              let valid = result["valid"] as? Bool else {
            return false
        }
        return valid
    }

    // MARK: - Private Helpers

    private static func callFFI(
        _ jsonInput: String,
        _ fn: (UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    ) throws -> [String: Any] {
        let cInput = jsonInput.cString(using: .utf8)!
        let cResult = cInput.withUnsafeBufferPointer { buf in
            fn(UnsafeMutablePointer(mutating: buf.baseAddress!))
        }
        defer { FreeString(cResult) }

        guard let result = cResult else {
            throw WalletError.nullResponse
        }

        let resultStr = String(cString: result)
        let dict = try parseJSON(resultStr)

        if let error = dict["error"] as? String {
            throw WalletError.goError(error)
        }

        return dict
    }

    private static func parseJSON(_ str: String) throws -> [String: Any] {
        guard let data = str.data(using: .utf8),
              let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw WalletError.invalidJSON(str)
        }
        return dict
    }

    private static func jsonString(_ dict: [String: Any]) -> String {
        let data = try! JSONSerialization.data(withJSONObject: dict)
        return String(data: data, encoding: .utf8)!
    }

    private static func parseAddressInfo(_ dict: [String: Any]) throws -> AddressInfo {
        guard let pubKey = dict["pubKey"] as? String,
              let address = dict["address"] as? String,
              let account = dict["account"] as? UInt32,
              let index = dict["index"] as? UInt32 else {
            throw WalletError.invalidResponse("missing address fields")
        }
        let zone = (dict["zone"] as? [Int])?.map { UInt8($0) } ?? [0, 0]
        let isQi = dict["isQi"] as? Bool ?? false
        return AddressInfo(
            pubKey: pubKey,
            address: address,
            account: account,
            index: index,
            zone: zone,
            isQi: isQi
        )
    }
}

enum WalletError: LocalizedError {
    case nullResponse
    case invalidJSON(String)
    case invalidResponse(String)
    case goError(String)

    var errorDescription: String? {
        switch self {
        case .nullResponse: return "Null response from Go library"
        case .invalidJSON(let s): return "Invalid JSON: \(s.prefix(100))"
        case .invalidResponse(let s): return "Invalid response: \(s)"
        case .goError(let s): return "Go error: \(s)"
        }
    }
}
