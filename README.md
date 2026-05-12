# SRProbe iOS

This is a benign reachability probe for the dyld/XNU shared-region syscall path.
It does **not** attempt to trigger a malformed slide-info OOB write. It only logs syscall reachability and error codes.

## Build/install

Open `SRProbe.xcodeproj` in Xcode, set your Team under Signing & Capabilities, change the bundle identifier if needed, then run on your iPhone.

Or from Terminal on macOS:

```zsh
./build_and_export_ipa.sh YOUR_TEAM_ID com.your.bundle.SRProbe
```

The exported IPA will be under `build/export/`.

## Logs to copy

In Xcode console, copy all lines containing:

```text
[SR-PROBE]
```

Useful host-side log stream:

```zsh
log stream --predicate 'eventMessage CONTAINS "shared_region" OR eventMessage CONTAINS "sandbox" OR eventMessage CONTAINS "AMFI" OR eventMessage CONTAINS "dyld" OR eventMessage CONTAINS "SR-PROBE"' --style compact
```

## Expected value

The key outputs are:

- `syscall294 shared_region_check_np`
- `syscall536 empty`
- `syscall536 bad_fd_no_slide`
- `syscall536 container_file_no_slide`
- `syscall536 container_file_with_VM_PROT_SLIDE_benign`
- `shared_region_check_np(NULL)`
- `posix_spawn self`

