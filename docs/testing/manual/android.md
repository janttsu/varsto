# Android: manual test checklist

Build id: ____   Device / OS version: ____   Date (UTC): ____

## Common
- [ ] Install and first launch
- [ ] Alpha warning shown and must be acknowledged
- [ ] Create vault; recovery phrase flow
- [ ] Unlock with passphrase of any length; wrong passphrase handling
- [ ] Add storage (S3 keys, local folder)
- [ ] Sync a folder in both directions
- [ ] Selective sync: placeholders, download on open, free up space
- [ ] Version history, trash and restore
- [ ] Transfer progress is non-blocking (inline per-file status, small speed bar)
- [ ] Language switch; light and dark theme
- [ ] Update and uninstall

## Platform specific
- [ ] Biometric unlock bound to hardware key store; passphrase fallback
- [ ] Wrong passphrase wipe counter (if enabled)
- [ ] NFC and USB-C security key unlock; Strongroom folders
- [ ] Camera auto upload: new photos, videos, HEIC, background, free-up-space only after durability check
- [ ] Offline pinned files stay encrypted on device; open works in airplane mode
- [ ] Background sync, Doze and battery saver behaviour
- [ ] Local network sync between two devices without internet
- [ ] Remote wipe command received and executed

## Notes
