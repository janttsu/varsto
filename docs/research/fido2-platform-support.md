# FIDO2 hmac-secret and WebAuthn PRF: platform support

> **Research note, design stage.** This document records what the cited sources say about using a FIDO2 security key to derive secrets (CTAP2 `hmac-secret`, exposed to web and platform APIs as the WebAuthn `prf` extension) from a native application. It is not a decision. No hardware was tested for this note. Anything the sources did not state is marked "not verified".
>
> All sources were read on **2026-10-08** (UTC). Source numbers in tables refer to the list at the end.

## Terms

- **hmac-secret** is the CTAP2 extension: the authenticator computes HMAC-SHA-256 over one or two 32-byte salts, keyed with a secret that belongs to one credential, and returns 32 or 64 bytes. The secret must be enabled when the credential is created; it cannot be added to an existing credential [S12].
- **PRF** is the WebAuthn name for the same feature. Platform APIs that expose PRF first hash the caller's input into the salt: the Windows header documents `SHA-256(UTF8("WebAuthn PRF") || 0x00 || value)` [S1]. A raw hmac-secret call (for example through libfido2) sends the salt as given. The same input therefore gives different secrets through the two routes unless the application applies the same transform on every platform.
- **hmac-secret-mc** returns the secret already during credential creation; the Yubico SDK documentation says it needs YubiKey firmware 5.8 or later [S12].

## Summary table

| Platform | API | hmac-secret or PRF available | Min OS version | Needs admin/root | Notes | Sources |
| --- | --- | --- | --- | --- | --- | --- |
| Windows | Windows WebAuthn API (`webauthn.h`, `webauthn.dll`), or libfido2 which can use it (`windows://hello`) | Yes for external security keys through the PRF fields of the WebAuthn API. The old `hmac-secret` extension identifier is documented as not supported for assertions; use the PRF fields instead. Windows Hello (platform authenticator) is reported to lack hmac-secret. | WebAuthn API: Windows 10 version 1903 or later. The Windows build that first has the PRF fields: not verified (the header ties them to API versions 4 and 6; no version-to-build table was found). | Via the WebAuthn API: not stated as required. Direct USB HID access: third parties report administrator rights are required since 1903; not verified from Microsoft sources. | Check `WebAuthNGetApiVersionNumber` at run time. Salts are hashed with the "WebAuthn PRF" prefix by default; a flag lets the caller pass raw hmac-secret salts. libfido2 supports hmac-secret through `windows://hello` since 1.11.0 and 64-byte salts since 1.17.0. | S1, S2, S3, S4, S5, S6 |
| macOS | libfido2 over IOKit HID, or Apple AuthenticationServices | libfido2: yes (hmac-secret API in `fido_assert_set_hmac_salt`). AuthenticationServices: PRF API for passkeys since macOS 15; a `prf` property on security-key requests is documented from macOS 26.4. | libfido2: no OS minimum stated. AuthenticationServices security-key PRF: 26.4. | Not stated for libfido2; not verified. | Yubico reported in mid-2025 that Safari did not pass PRF to external keys on macOS 15 while Chrome did. The behaviour of the native 26.4 API with hardware keys was not tested. | S5, S7, S8, S9, S10 |
| Linux | libfido2 (hidraw, udev) | Yes (`FIDO_EXT_HMAC_SECRET`, `fido_assert_set_hmac_salt`) | No OS minimum stated; requires libcbor, OpenSSL 3.0+, zlib, libudev | No root if a udev rule grants the user access to the `hidraw` device | libfido2 1.17.0 (2026-04-15) is current in the README. Distribution packages may be older. | S5, S6, S11 |
| Android | Credential Manager (`androidx.credentials`) for passkeys, or a vendor SDK that talks CTAP2 over USB host or NFC (YubiKit for Android) | Credential Manager: the release notes mention PRF support (creation fixed for Android 13 and below in 1.3.0-alpha04). Use with external security keys through Credential Manager: not verified. YubiKit for Android: yes, `HmacSecretExtension` implements prf, hmac-secret and hmac-secret-mc. | Credential Manager passkeys: Android 9 (API 28). YubiKit FIDO Android UI module: API 23. YubiKit core minimum: not verified. | No (USB host permission prompt per connection) | Yubico reported in mid-2025 that Chrome on Android supported PRF with a security key over USB but not NFC. The vendor SDK route supports both USB and NFC. | S13, S14, S15, S16, S17, S12 |
| iOS and iPadOS | Apple AuthenticationServices (`ASAuthorizationSecurityKeyPublicKeyCredential*`), or YubiKit for iOS | AuthenticationServices: PRF input and output types exist since iOS 18; the `prf` property on security-key registration and assertion requests is documented from iOS 26.4. YubiKit for iOS: no hmac-secret or extension API found in the FIDO2 session or response headers. | AuthenticationServices security-key PRF: iOS and iPadOS 26.4. Security-key requests without PRF: iOS and iPadOS 15. | No | YubiKit for iOS: NFC and the Lightning accessory work; the README states that a USB-C connection supports only smart-card applications, not U2F, FIDO2 or OTP. Yubico reported in mid-2025 that iOS 18 did not pass PRF data to external keys. Transport support (NFC, USB-C) of the native security-key API: not verified. | S7, S8, S9, S10, S12, S18, S19 |

## Per platform

### Windows

- The Win32 WebAuthn API is available from Windows 10 version 1903 and exposes external FIDO2 security keys and Windows Hello [S2, S3]. Microsoft's overview page states ECC support from Windows 11 22H2 and plugin passkey managers from Windows 11 24H2; it does not say which Windows build first supports PRF [S3].
- `webauthn.h` documents API versions 1 to 9. In the header comments, `WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS` version 6 (field `pHmacSecretSaltValues`) is listed under API version 4, and `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS` version 6 (field `bEnablePrf`) under API version 6 [S1]. An application must call `WebAuthNGetApiVersionNumber` and handle older versions.
- The legacy `hmac-secret` extension identifier is documented in the header as supported for MakeCredential only and "Not Supported" for GetAssertion; assertion-time secrets go through the PRF fields [S1].
- Yubico's PRF guide (mid-2025) lists the Windows Hello platform authenticator as lacking hmac-secret and YubiKeys as working [S4]. The Microsoft docs checked do not say this.
- Administrator rights: Microsoft's pages checked do not mention them. Two third-party pages (a Token2 tool page and an OpenSSH Windows Hello project) state that since Windows 10 1903 direct access to FIDO devices needs administrator rights and that the WebAuthn API is the non-elevated route [S20, S21]. Treat as not verified.
- libfido2 can use the Windows WebAuthn API (`windows://hello`); since version 1.10.0 it falls back to its own HID code if `webauthn.dll` is missing [S6].

### macOS

- libfido2 lists macOS among supported platforms and has native HID support (IOKit) [S5, S6]. Administrator rights and any macOS privacy prompts for HID access: not verified.
- Apple's AuthenticationServices has PRF input and output types from iOS 18 and macOS 15 [S7]. The security-key registration and assertion request classes exist since iOS 15 and macOS 12 [S8, S9]; their `prf` properties are documented from iOS, iPadOS, macCatalyst and macOS 26.4 [S10]. Which key transports and which keys work through this API was not verified.
- Yubico's guide (mid-2025) reported that on macOS 15 Chrome could use PRF with a YubiKey while Safari could not [S4].

### Linux

- libfido2 is the usual library: hmac-secret is available when creating (`fido_cred_set_extensions`, `FIDO_EXT_HMAC_SECRET`) and asserting (`fido_assert_set_hmac_salt`, `fido_assert_hmac_secret_ptr`) [S5, S11].
- The README says a udev rule may be needed so a normal user can reach the device; with a rule, root is not needed [S5].

### Android

- Credential Manager passkeys work on Android 9 (API 28) and later [S13]. The Jetpack release notes list "Support PRF creation for Android versions 13 and below" in `androidx.credentials` 1.3.0-alpha04 [S14]. Whether Credential Manager can route PRF to an external USB or NFC security key for a third-party app was not found in Android documentation: not verified.
- YubiKit for Android includes a FIDO module with a `HmacSecretExtension` that implements prf, hmac-secret and hmac-secret-mc [S12, S15]. The library supports USB and NFC YubiKeys [S16]. A separate FIDO Android UI module requires API 23 [S16]. This route works with Yubico's own keys; other vendors' keys speak the same CTAP2 protocol, but this was not verified.
- Yubico's guide (mid-2025) lists Chrome on Android as supporting PRF with a roaming authenticator over USB but not NFC [S4].

### iOS and iPadOS

- Apple documents PRF types from iOS 18 and, for security-key requests, the `prf` property from iOS 26.4 [S7, S10]. In mid-2025 Yubico reported that iOS 18 did not pass PRF extension data to external keys, calling this a critical limitation [S4]. Whether 26.4 fixes it for hardware keys: not verified.
- YubiKit for iOS supports FIDO2 over NFC and the Lightning accessory. Its README states that a YubiKey connected over USB-C on iOS 16 or later supports only smart-card applications, not U2F, FIDO2 or OTP [S18]. No hmac-secret or extension handling was found in the FIDO2 session and assertion response headers [S19]. Treat YubiKit for iOS as not offering hmac-secret.
- NFC access in a third-party app needs the NFC tag-reading entitlement and the FIDO AID in the app configuration [S18].

## Security keys known to list hmac-secret

Source: the FIDO Alliance Metadata Service (MDS3) blob, number 290, next update 2026-11-01, read on 2026-10-08 [S22]. Of 520 entries, 317 list `hmac-secret` in `authenticatorGetInfo.extensions`. The blob's signature was not verified for this note; only its payload was decoded. An MDS entry describes a certified model and firmware profile; it is not proof that a given unit behaves the same. Check each key at run time (CTAP2 `authenticatorGetInfo`, for example `fido2-token -I`).

| Family | Form factors listed | MDS lists hmac-secret | Notes |
| --- | --- | --- | --- |
| YubiKey 5 Series (including NFC, Lightning, FIPS and CCN variants) | USB-A or USB-C, NFC, Lightning | Yes, in most entries; some older entries have no extension data | hmac-secret-mc needs firmware 5.8 or later [S12] |
| YubiKey Bio Series | USB | Yes | |
| Security Key by Yubico, Security Key NFC, Security Key Series | USB, NFC | Yes in the entries checked; some older entries list none | |
| Nitrokey 3 | USB | Yes (entry "Nitrokey 3 AM") | |
| SoloKeys Solo and Solo Tap | USB, NFC | Yes | |
| TOKEN2 FIDO2 Security Key, PIN Plus series | USB, NFC | Yes | |
| Google Titan Security Key v2 | USB, NFC | Yes | |
| Feitian ePass FIDO2, BioPass FIDO2 | USB, NFC | Yes in the FIDO2 entries; U2F-only entries list none | |
| Swissbit iShield Key and Key 2 | USB, NFC | Yes | |
| HID Crescendo, Thales IDPrime FIDO Bio | NFC, USB | Yes | |
| Kensington VeriMark | USB, NFC | Yes | |
| OnlyKey | USB | Yes | |
| Excelsecu eSecu | USB, NFC, Bluetooth | Yes in several entries | |
| Older or U2F-only keys (for example YubiKey NEO, YK4 Series, Yubikey Edge, Feitian ePass FIDO Security Key, HyperFIDO U2F) | various | No | U2F-only; no CTAP2 extensions |

## Conclusion: consequences for S-005 and S-012 (questions for the maintainer)

These are questions, not decisions. S-005 requires FIDO2 security key support over USB and NFC on all platforms; S-012 requires Strongroom folder keys to be wrapped with a FIDO2 hmac-secret.

1. **One derivation on every platform.** Platform PRF APIs hash the input; raw hmac-secret does not. Which transform does the project fix in its specification so that a secret derived on Windows, Linux, Android and iOS from the same key and credential is identical? (Relevant to S-012 and to the key hierarchy.)
2. **Native versus vendor route per platform.** Windows and Linux have working routes (WebAuthn API, libfido2). On Android the vendor SDK route has hmac-secret and USB and NFC; the Credential Manager route is not verified for external keys. On iOS the vendor SDK route has no hmac-secret and no USB-C FIDO2, and the Apple API documents security-key PRF only from 26.4. Is the project willing to require iOS and iPadOS 26.4 or later for Strongroom, or should Strongroom be limited on iOS until hardware tests exist?
3. **S-005 transports on iOS.** If YubiKit for iOS does not support FIDO2 over USB-C and native support is not verified, does S-005 ("USB, NFC on all platforms") allow NFC-only on iOS for the first releases?
4. **Platform authenticators.** Windows Hello is reported to lack hmac-secret, and platform passkeys differ from roaming keys. Does S-012 require an external security key, so that Strongroom cannot be unlocked with a platform authenticator alone?
5. **Credential lifecycle.** hmac-secret must be enabled when the credential is created and cannot be added later. Each key has its own credential-bound secret, so two keys produce different secrets for the same input. How should a spare key be enrolled (a second wrapped copy of each folder key per key)? Who approves requiring `hmac-secret` in `authenticatorGetInfo` as a pairing precondition?
6. **Key whitelist.** Should the project maintain a tested-keys list, given that the metadata lists many models but behaviour differs by firmware (for example hmac-secret-mc on YubiKey firmware 5.8 and later)?
7. **Elevation on Windows.** Should the Windows client use only the WebAuthn API (no raw HID) to avoid asking users for administrator rights? The administrator claim is not verified from Microsoft sources.
8. **Hardware testing.** Who runs the device checks listed in [docs/testing/manual](../testing/manual/README.md) for PRF with real keys on each platform, since none was run for this note?

## Sources

All checked on 2026-10-08.

| No. | Source | URL |
| --- | --- | --- |
| S1 | Microsoft, `webauthn.h` (official repository): API versions, PRF fields, hmac-secret notes | <https://raw.githubusercontent.com/microsoft/webauthn/master/webauthn.h> |
| S2 | Microsoft Learn, WebAuthn API portal: runtime requirements (Windows 10 version 1903 and later, Windows 11) | <https://learn.microsoft.com/en-us/windows/win32/webauthn/-webauthn-portal> |
| S3 | Microsoft Learn, WebAuthn APIs for passwordless authentication on Windows | <https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis> |
| S4 | Yubico, Developer's Guide to PRF (compatibility table "as of mid-2025") | <https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html> |
| S5 | Yubico, libfido2 README | <https://raw.githubusercontent.com/Yubico/libfido2/main/README.adoc> |
| S6 | Yubico, libfido2 release notes (NEWS) | <https://raw.githubusercontent.com/Yubico/libfido2/main/NEWS> |
| S7 | Apple, `ASAuthorizationPublicKeyCredentialPRFRegistrationInput` (iOS 18.0, macOS 15.0) | <https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfregistrationinput-swift.struct> |
| S8 | Apple, `ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest` (iOS 15.0, macOS 12.0) | <https://developer.apple.com/documentation/authenticationservices/asauthorizationsecuritykeypublickeycredentialregistrationrequest> |
| S9 | Apple, `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest` | <https://developer.apple.com/documentation/authenticationservices/asauthorizationsecuritykeypublickeycredentialassertionrequest> |
| S10 | Apple, `prf` property on the security-key registration and assertion requests (26.4.0) | <https://developer.apple.com/documentation/authenticationservices/asauthorizationsecuritykeypublickeycredentialregistrationrequest/prf-964zl> and <https://developer.apple.com/documentation/authenticationservices/asauthorizationsecuritykeypublickeycredentialassertionrequest/prf-7pp6b> |
| S11 | Yubico, libfido2 manual pages `fido_assert_set_hmac_salt` and `fido_cred_set_extensions` | <https://developers.yubico.com/libfido2/Manuals/fido_assert_set_hmac_salt.html> and <https://developers.yubico.com/libfido2/Manuals/fido_cred_set_extensions.html> |
| S12 | Yubico, YubiKey SDK for .NET: FIDO2 hmac-secret and hmac-secret-mc extensions | <https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html> |
| S13 | Android Developers, About passkeys (Android 9 / API 28) | <https://developer.android.com/identity/passkeys> |
| S14 | Android Developers, Jetpack Credentials release notes (1.3.0-alpha04, PRF) | <https://developer.android.com/jetpack/androidx/releases/credentials> |
| S15 | Yubico, yubikit-android `HmacSecretExtension.java` | <https://raw.githubusercontent.com/Yubico/yubikit-android/main/fido/src/main/java/com/yubico/yubikit/fido/client/extensions/HmacSecretExtension.java> |
| S16 | Yubico, yubikit-android README (USB and NFC, FIDO modules, API 23 for the UI module) | <https://raw.githubusercontent.com/Yubico/yubikit-android/main/README.adoc> |
| S17 | Android Developers, Credential Manager (replaces legacy local FIDO2 credentials) | <https://developer.android.com/identity/sign-in/credential-manager> |
| S18 | Yubico, yubikit-ios README (NFC, Lightning, USB-C smart-card only) | <https://raw.githubusercontent.com/Yubico/yubikit-ios/main/README.md> |
| S19 | Yubico, yubikit-ios `YKFFIDO2Session.h` and `YKFFIDO2GetAssertionResponse.h` (no hmac-secret handling found) | <https://github.com/Yubico/yubikit-ios> |
| S20 | Token2, FIDO2.1 Security Key Management Tool (third-party statement on administrator rights) | <https://www.token2.com/site/page/fido2-1-security-key-management-tool-gui-for-fido2-manage-exe> |
| S21 | tavrez/openssh-sk-winhello (third-party statement on administrator rights) | <https://github.com/tavrez/openssh-sk-winhello> |
| S22 | FIDO Alliance, Metadata Service (MDS3) blob no. 290 | <https://mds3.fidoalliance.org/> |
