import SwiftUI

struct ContentView: View {
    @State private var logs: [LogEntry] = []
    @State private var isRunning = false

    var body: some View {
        NavigationView {
            VStack {
                if isRunning {
                    ProgressView("Running tests...")
                        .padding()
                }
                List(logs) { entry in
                    HStack(alignment: .top) {
                        Image(systemName: entry.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundColor(entry.passed ? .green : .red)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.title)
                                .font(.headline)
                            Text(entry.detail)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 2)
                }
                Button("Run All Tests") {
                    runTests()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isRunning)
                .padding()
            }
            .navigationTitle("Quai Wallet Test")
        }
        .onAppear { runTests() }
    }

    func runTests() {
        isRunning = true
        logs = []
        DispatchQueue.global(qos: .userInitiated).async {
            let results = WalletTests.runAll()
            DispatchQueue.main.async {
                logs = results
                isRunning = false
            }
        }
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let title: String
    let detail: String
    let passed: Bool
}

// MARK: - Test Suite

struct WalletTests {
    static func runAll() -> [LogEntry] {
        var results: [LogEntry] = []

        // Test 1: Validate mnemonic
        results.append(testValidateMnemonic())

        // Test 2: Create wallet from phrase
        results.append(testCreateFromPhrase())

        // Test 3: Create random wallet
        results.append(testCreateRandom())

        // Test 4: Derive Quai address
        results.append(testDeriveQuaiAddress())

        // Test 5: Derive Qi address
        results.append(testDeriveQiAddress())

        // Test 6: Derive addresses for different zones
        results.append(testDeriveMultipleZones())

        // Test 7: Get private key
        results.append(testGetPrivateKey())

        // Test 8: Sign Quai transaction
        results.append(testSignQuaiTransaction())

        // Test 9: Serialize and deserialize
        results.append(testSerializeDeserialize())

        // Test 10: Deterministic derivation
        results.append(testDeterministicDerivation())

        // Test 11: Benchmark - derive 100 addresses
        results.append(testBenchmark100Addresses())

        // Test 12: Benchmark - 100 ECDSA signatures
        results.append(testBenchmark100Signatures())

        return results
    }

    static let testPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    static func testValidateMnemonic() -> LogEntry {
        let valid = QuaiWallet.isValidMnemonic(testPhrase)
        let invalid = !QuaiWallet.isValidMnemonic("not a valid mnemonic")
        let passed = valid && invalid
        return LogEntry(
            title: "Validate Mnemonic",
            detail: passed ? "Valid phrase accepted, invalid rejected" : "FAILED",
            passed: passed
        )
    }

    static func testCreateFromPhrase() -> LogEntry {
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            return LogEntry(
                title: "Create from Phrase",
                detail: "walletId: \(wallet.walletId.prefix(8))...",
                passed: true
            )
        } catch {
            return LogEntry(title: "Create from Phrase", detail: error.localizedDescription, passed: false)
        }
    }

    static func testCreateRandom() -> LogEntry {
        do {
            let (wallet, phrase) = try QuaiWallet.createRandom(coinType: 994)
            let wordCount = phrase.split(separator: " ").count
            let passed = wordCount == 12 && !wallet.walletId.isEmpty
            return LogEntry(
                title: "Create Random Wallet",
                detail: "\(wordCount) words: \(phrase.split(separator: " ").prefix(3).joined(separator: " "))...",
                passed: passed
            )
        } catch {
            return LogEntry(title: "Create Random Wallet", detail: error.localizedDescription, passed: false)
        }
    }

    static func testDeriveQuaiAddress() -> LogEntry {
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let info = try wallet.deriveAddress(account: 0, zone: [0, 0])
            let passed = !info.address.isEmpty && !info.isQi
            return LogEntry(
                title: "Derive Quai Address (Cyprus1)",
                detail: "\(info.address) (index=\(info.index))",
                passed: passed
            )
        } catch {
            return LogEntry(title: "Derive Quai Address", detail: error.localizedDescription, passed: false)
        }
    }

    static func testDeriveQiAddress() -> LogEntry {
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 969)
            let info = try wallet.deriveAddress(account: 0, zone: [0, 0])
            let passed = !info.address.isEmpty && info.isQi
            return LogEntry(
                title: "Derive Qi Address (Cyprus1)",
                detail: "\(info.address) (index=\(info.index))",
                passed: passed
            )
        } catch {
            return LogEntry(title: "Derive Qi Address", detail: error.localizedDescription, passed: false)
        }
    }

    static func testDeriveMultipleZones() -> LogEntry {
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let zones: [[UInt8]] = [[0, 0], [0, 1], [1, 0]]
            var details: [String] = []
            for zone in zones {
                let info = try wallet.deriveAddress(account: 0, zone: zone)
                details.append("[\(zone[0]),\(zone[1])]: \(info.address.prefix(10))...")
            }
            return LogEntry(
                title: "Derive Multiple Zones",
                detail: details.joined(separator: "\n"),
                passed: true
            )
        } catch {
            return LogEntry(title: "Derive Multiple Zones", detail: error.localizedDescription, passed: false)
        }
    }

    static func testGetPrivateKey() -> LogEntry {
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let info = try wallet.deriveAddress(account: 0, zone: [0, 0])
            let key = try wallet.getPrivateKey(address: info.address)
            let passed = key.hasPrefix("0x") && key.count == 66
            return LogEntry(
                title: "Get Private Key",
                detail: "\(key.prefix(10))... (\(key.count) chars)",
                passed: passed
            )
        } catch {
            return LogEntry(title: "Get Private Key", detail: error.localizedDescription, passed: false)
        }
    }

    static func testSignQuaiTransaction() -> LogEntry {
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let info = try wallet.deriveAddress(account: 0, zone: [0, 0])
            let txHex = try wallet.signQuaiTransaction(
                address: info.address,
                chainId: 9000,
                nonce: 0,
                gasPrice: "1000000000",
                gas: 21000,
                to: info.address,
                value: "1000000000000000000",
                zone: [0, 0]
            )
            let passed = txHex.hasPrefix("0x") && txHex.count > 20
            return LogEntry(
                title: "Sign Quai Transaction",
                detail: "\(txHex.count / 2 - 1) bytes: \(txHex.prefix(20))...",
                passed: passed
            )
        } catch {
            return LogEntry(title: "Sign Quai Transaction", detail: error.localizedDescription, passed: false)
        }
    }

    static func testSerializeDeserialize() -> LogEntry {
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let info1 = try wallet.deriveAddress(account: 0, zone: [0, 0])
            let json = try wallet.serialize()
            let restored = try QuaiWallet.deserialize(json)
            let info2 = try restored.deriveAddress(account: 0, zone: [0, 0])
            // After restore, next address should be different (index advanced)
            let passed = info1.address != info2.address
            return LogEntry(
                title: "Serialize / Deserialize",
                detail: "Original: \(info1.address.prefix(10))..., After restore: \(info2.address.prefix(10))...",
                passed: passed
            )
        } catch {
            return LogEntry(title: "Serialize / Deserialize", detail: error.localizedDescription, passed: false)
        }
    }

    static func testDeterministicDerivation() -> LogEntry {
        do {
            let w1 = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let w2 = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let info1 = try w1.deriveAddress(account: 0, zone: [0, 0])
            let info2 = try w2.deriveAddress(account: 0, zone: [0, 0])
            let passed = info1.address == info2.address && info1.index == info2.index
            return LogEntry(
                title: "Deterministic Derivation",
                detail: "Same phrase -> same address: \(info1.address.prefix(10))...",
                passed: passed
            )
        } catch {
            return LogEntry(title: "Deterministic Derivation", detail: error.localizedDescription, passed: false)
        }
    }

    static func testBenchmark100Addresses() -> LogEntry {
        let count = 100
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let start = CFAbsoluteTimeGetCurrent()
            for _ in 0..<count {
                _ = try wallet.deriveAddress(account: 0, zone: [0, 0])
            }
            let elapsed = CFAbsoluteTimeGetCurrent() - start
            let perAddr = elapsed / Double(count) * 1000.0 // ms per address
            return LogEntry(
                title: "Benchmark: 100 Addresses",
                detail: String(format: "%.3f s total, %.2f ms/addr", elapsed, perAddr),
                passed: true
            )
        } catch {
            return LogEntry(title: "Benchmark: 100 Addresses", detail: error.localizedDescription, passed: false)
        }
    }

    static func testBenchmark100Signatures() -> LogEntry {
        let count = 100
        do {
            let wallet = try QuaiWallet(phrase: testPhrase, coinType: 994)
            let info = try wallet.deriveAddress(account: 0, zone: [0, 0])

            // Empty data payload
            let startEmpty = CFAbsoluteTimeGetCurrent()
            for i in 0..<count {
                _ = try wallet.signQuaiTransaction(
                    address: info.address,
                    chainId: 9000,
                    nonce: UInt64(i),
                    gasPrice: "1000000000",
                    gas: 21000,
                    to: info.address,
                    value: "1000000000000000000",
                    zone: [0, 0]
                )
            }
            let elapsedEmpty = CFAbsoluteTimeGetCurrent() - startEmpty
            let perSigEmpty = elapsedEmpty / Double(count) * 1000.0

            // 10 KB data payload (hex-encoded = 20480 chars)
            let bigDataHex = "0x" + String(repeating: "ab", count: 10 * 1024)
            let startData = CFAbsoluteTimeGetCurrent()
            for i in 0..<count {
                _ = try wallet.signQuaiTransaction(
                    address: info.address,
                    chainId: 9000,
                    nonce: UInt64(i),
                    gasPrice: "1000000000",
                    gas: 200000,
                    to: info.address,
                    value: "0",
                    data: bigDataHex,
                    zone: [0, 0]
                )
            }
            let elapsedData = CFAbsoluteTimeGetCurrent() - startData
            let perSigData = elapsedData / Double(count) * 1000.0

            return LogEntry(
                title: "Benchmark: 100 ECDSA Sigs",
                detail: String(format: "empty: %.2f ms/sig, 10KB: %.2f ms/sig", perSigEmpty, perSigData),
                passed: true
            )
        } catch {
            return LogEntry(title: "Benchmark: 100 ECDSA Sigs", detail: error.localizedDescription, passed: false)
        }
    }
}
