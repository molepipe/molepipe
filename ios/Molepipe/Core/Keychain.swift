import Foundation
import Security
import LocalAuthentication

/// Keychain is a small wrapper over the iOS keychain for the handful of tiny
/// secrets the shell keeps on-device.
///
/// What it is NOT: the BIP39 seed does not live here. The seed stays in the Go
/// store's password-encrypted `identity.enc`, whose single root of truth is the
/// recovery phrase and which must remain recoverable on any device. Putting the
/// seed — or a device-only key that gates it — in the keychain would bind the
/// account to this one device and break cross-device recovery. So the keychain
/// here only holds *local conveniences* that can always be re-entered or
/// regenerated, chiefly an opt-in "unlock with Face ID" copy of the vault
/// password (biometric-gated). Losing them costs a password re-entry, never the
/// account.
///
/// Every item is device-only (`…ThisDeviceOnly`): never synced to iCloud
/// Keychain, never included in a backup.
enum Keychain {

    enum Key {
        /// Opt-in biometric-unlock copy of the vault password. Biometric-gated.
        static let vaultPassword = "vault-password"
    }

    /// AfterFirstUnlock: readable once the device has been unlocked at least once
    /// since boot (so a backgrounded launch can use it), but not before — and
    /// ThisDeviceOnly keeps it off iCloud Keychain and out of backups.
    private static let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    private static var service: String {
        Bundle.main.bundleIdentifier ?? "org.molepipe.molepipe"
    }

    // MARK: - Write

    /// Store (or replace) a secret. `biometricGated` requires Face ID / Touch ID
    /// / device passcode on every read (use it for the vault password). Returns
    /// false on failure — e.g. biometric gating requested on a device with no
    /// passcode set, where a protected item cannot be created.
    @discardableResult
    static func set(_ value: Data, for key: String, biometricGated: Bool = false) -> Bool {
        delete(key) // SecItemAdd fails on a duplicate; access control can't be updated in place.

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: value,
        ]

        if biometricGated {
            var acError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, accessible, .userPresence, &acError
            ) else {
                return false
            }
            query[kSecAttrAccessControl as String] = access
        } else {
            query[kSecAttrAccessible as String] = accessible
        }

        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    @discardableResult
    static func set(_ string: String, for key: String, biometricGated: Bool = false) -> Bool {
        set(Data(string.utf8), for: key, biometricGated: biometricGated)
    }

    // MARK: - Read

    /// Read a secret. For a biometric-gated item this presents the system
    /// Face ID / passcode prompt showing `reason`; the call BLOCKS until the user
    /// responds, so never call it on the main thread. Returns nil if the item is
    /// absent or the user cancels / fails authentication.
    static func get(_ key: String, reason: String? = nil) -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let reason = reason {
            let ctx = LAContext()
            ctx.localizedReason = reason
            query[kSecUseAuthenticationContext as String] = ctx
        }
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else {
            return nil
        }
        return out as? Data
    }

    static func string(_ key: String, reason: String? = nil) -> String? {
        get(key, reason: reason).flatMap { String(data: $0, encoding: .utf8) }
    }

    /// Whether an item exists, without triggering a biometric prompt (metadata
    /// only, no data returned). Lets the UI decide whether to offer biometric
    /// unlock before prompting.
    static func has(_ key: String) -> Bool {
        let ctx = LAContext()
        ctx.interactionNotAllowed = true // never prompt: metadata check only
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecUseAuthenticationContext as String: ctx,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        // errSecInteractionNotAllowed means it exists but is gated — still "present".
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // MARK: - Delete

    /// Remove a secret. Safe to call when absent.
    @discardableResult
    static func delete(_ key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
