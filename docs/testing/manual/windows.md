# Windows: manual test checklist

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
- [ ] Cloud Files placeholders and Explorer integration
- [ ] Security key (FIDO2) unlock and Strongroom folders
- [ ] Antivirus or indexer does not trigger mass downloads
- [ ] Long paths, case-insensitive name conflicts

## Notes
