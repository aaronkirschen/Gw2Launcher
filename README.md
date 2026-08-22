# Gw2Launcher — .NET 10 and Wine-compatible fork

This fork of [Healix/Gw2Launcher](https://github.com/Healix/Gw2Launcher) modernizes the launcher to .NET 10 and replaces its low-level mutex-killing implementation with a DLL proxy designed to work on both Windows and Wine/Proton.

Gw2Launcher manages multiple Guild Wars 2 accounts and allows multiple clients to run at the same time.

## Download

Download the latest self-contained `win-x64` ZIP from [GitHub Releases](../../releases).

Extract the ZIP somewhere writable and run:

- **Windows:** `Gw2Launcher.exe`
- **Linux/Wine:** `wine Gw2Launcher.exe`

The release is self-contained; users do not need to install .NET separately.

> **Current test status:** the self-contained Release build and a clean launch under Wine 11.16 have been verified on Arch Linux. Full multi-account launching and mutex-proxy behavior still require end-to-end testing with Guild Wars 2 before the first stable release.

## What this fork changes

### Wine-compatible multi-instance handling

Guild Wars 2 creates a named mutex to prevent multiple clients from running. Upstream Gw2Launcher finds and closes that mutex using Windows NT handle APIs.

This fork instead builds and embeds a `version.dll` proxy that:

1. Is deployed beside `Gw2-64.exe` when launching in multi-instance mode.
2. Forwards normal `version.dll` calls to the real system library.
3. Intercepts GW2's mutex creation and substitutes an unnamed mutex.
4. Sets `WINEDLLOVERRIDES=version=n,b` for Wine/Proton so the native proxy is loaded before Wine's built-in DLL.

The game still receives a valid mutex handle, but the named single-instance mutex is never created.

### Modern self-contained build

- Migrated from .NET Framework 4.7.2 to `net10.0-windows`
- Uses an SDK-style project
- Publishes a self-contained, single-file `win-x64` executable
- Builds the native mutex proxy from source with MinGW-w64
- Does not require users to install the .NET runtime

## Building on Arch Linux

Install the build dependencies:

```bash
sudo pacman -S --needed dotnet-sdk mingw-w64-gcc
```

Publish a Release build:

```bash
dotnet publish Gw2Launcher/Gw2Launcher.csproj \
  --configuration Release \
  --runtime win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  --output artifacts/publish
```

The primary outputs are:

```text
artifacts/publish/Gw2Launcher.exe
artifacts/publish/Gw2Launcher.dll.config
artifacts/publish/Gw2Launcher.pdb
```

The project builds `Gw2Launcher/Resources/version_proxy.dll` automatically and embeds it into the launcher executable.

## Automated builds and releases

The GitHub Actions workflow supports:

- Manual runs that produce downloadable test artifacts
- Self-contained `win-x64` ZIPs
- Separate debug symbols
- SHA-256 checksums
- Automatic GitHub Release creation only for deliberately pushed `v*` tags

A tag should only be created after its exact build has passed Wine and GW2 multi-instance testing.

## Usage notes inherited from upstream

See the [upstream wiki](https://github.com/Healix/Gw2Launcher/wiki) for general configuration and usage information.

### Sharing the GW2 archive

GW2 locks access to `Gw2.dat`, which prevents other processes from reading it. Gw2Launcher uses `-shareArchive` when launching multiple clients.

When `-shareArchive` is enabled, GW2 cannot modify its files. To update the game or change settings that require archive access, launch it normally; Gw2Launcher handles this distinction.

### CefHost.exe remaining after closing GW2

GW2 may leave a renderer process active if the client closes while starting the renderer. Enable:

```text
Settings > Guild Wars 2 > Browser priority
```

to close remaining CefHost processes associated with an account.

### CEF creating unnecessary files

Enable:

```text
Settings > Guild Wars 2 > Management > Rename CEF on launch
```

to prevent redundant CEF copies and allow accounts to share the same files.

### Indefinite black screen at character selection

Useful mitigations include:

```text
Settings > Guild Wars 2 > Process priority while initializing the game: high
Settings > General > Launching > Timeout: relaunch after 15–30 seconds
Settings > General > Launching > Delay until the main window is loaded
```

## License

MIT. See [LICENSE.md](LICENSE.md).

The original Gw2Launcher is by Healix and its contributors.
