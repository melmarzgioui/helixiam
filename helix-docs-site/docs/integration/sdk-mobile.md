# Mobile SDK

Ship your own branded authenticator app — device enrolment, push approval, QR login, and transaction signing — backed by the phone's secure hardware.

## What it is

`helix_device` is the official mobile SDK, written in **Dart** and **Flutter-ready**. It embeds the full [device push factor](../authentication/device-push.md) into an app that carries *your* name, not a generic one:

- **Device enrolment** with hardware-key attestation
- **Push approval** with number matching
- **Cross-device QR confirm** to log in on a laptop or shared screen
- **Transaction signing** (WYSIWYS) for high-value actions

```bash
flutter pub add helix_device
```

## Capabilities

### Hardware-backed key store

Every credential is created and used inside the phone's secure hardware. The SDK's `DeviceKeyStore` interface backs onto the **iOS Secure Enclave** and the **Android Keystore**, and signing is **biometric-gated** — the key never leaves the device and can only be used with Face ID, Touch ID, or fingerprint.

```dart
import 'package:helix_device/helix_device.dart';

final device = HelixDevice(
  issuer: 'https://auth.example.com/realms/acme',
  keyStore: PlatformKeyStore(), // Secure Enclave / Android Keystore
);

// One-time enrolment with hardware-key attestation
await device.enroll(enrolmentToken);
```

### Push approval with number matching

```dart
device.pushChallenges.listen((challenge) async {
  // Show the browser's number; user taps the match
  await challenge.approve(selectedNumber: userChoice);
});
```

### Cross-device QR login

```dart
final scanned = await scanner.next();          // your QR scanner
await device.confirmQrLogin(scanned.payload);
```

### Transaction signing (WYSIWYS)

The exact details of an action are shown on the device and cryptographically bound to the signature — *what you see is what you sign*.

```dart
final tx = await device.nextTransaction();
// Render tx.summary (e.g. payee + amount) for the user to review
await tx.sign(); // biometric-gated signature over the bound details
```

!!! tip "Biometric-gated by design"
    Because signing keys live in the Secure Enclave / Android Keystore and require biometrics, an approval can only ever come from the enrolled device, in the user's hands.

## Pairs with the device push factor

This SDK is the client half of the [device push factor](../authentication/device-push.md). Enable that factor in the realm, register the device's FCM/APNs push token, and add the push or transaction-signing step to a [sign-in journey](../authentication/flows.md).

## See also

- [Device push & mobile app](../authentication/device-push.md)
- [Multi-factor authentication](../authentication/mfa.md)
- [TypeScript SDK](sdk-typescript.md)
- [OIDC quickstart](oidc-quickstart.md)
