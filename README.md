# Linux-Juce8-Patcher

Fix white or broken JUCE 8 Windows VST3 plugin editors on Linux/Wine/yabridge by applying known-safe binary patches.

This tool patches **specific known plugin builds**. It is not a blind patch-everything tool.

## Safety rules

- Always close your DAW/plugin host before patching.
- Always run `--dry-run` first.
- The patcher creates backups before writing.
- If a binary does not match a known signature, the patcher refuses to write.
- Unknown plugins should use `--probe`, not patch mode.

Backups go here:

```text
~/.local/share/plugin-binary-backups/
```

## Install

```bash
git clone https://github.com/DerpcatMusic/Linux-Juce8-Patcher.git
cd Linux-Juce8-Patcher
```

Requires Python 3. No Python packages are needed.

## Easiest use: pick plugins from a menu

Preview first:

```bash
python3 juce8_megapatcher.py --select --dry-run
```

If the preview looks right, patch the selected plugins:

```bash
python3 juce8_megapatcher.py --select
```

The selector shows known recipes, whether their default file path exists, and lets you choose by number:

```text
Known plugin recipes:
 1. filterverse      confirmed         found   Polyverse Filterverse
 2. kick-ninja       experimental      found   The Him DSP Kick Ninja
 3. soothe3          blocked-protected found   oeksound soothe3
 4. temperance-lite  confirmed         missing Eventide Temperance Lite
 5. temperance-pro   confirmed         found   Eventide Temperance Pro

Select plugins to patch (e.g. 1,3 or all; empty to cancel):
```

Examples:

```text
1       patch Filterverse only
1,5     patch Filterverse and Temperance Pro
all     patch all recipes shown by the selector
empty   cancel
```

## Patch all confirmed plugins

Preview confirmed recipes:

```bash
python3 juce8_megapatcher.py --dry-run
```

Patch confirmed recipes:

```bash
python3 juce8_megapatcher.py
```

Confirmed recipes are the ones believed safe enough for normal use. Experimental and blocked recipes are skipped by default.

## Patch one known plugin

```bash
python3 juce8_megapatcher.py --plugin filterverse --dry-run
python3 juce8_megapatcher.py --plugin filterverse
```

Available plugin slugs:

```bash
python3 juce8_megapatcher.py --list
```

Current recipes:

| Plugin | Slug | Status | Notes |
| --- | --- | --- | --- |
| Polyverse Filterverse | `filterverse` | confirmed | Confirmed working in Bitwig/yabridge after patching. |
| Eventide Temperance Pro | `temperance-pro` | confirmed | Confirmed working in Bitwig/yabridge after patching. |
| Eventide Temperance Lite | `temperance-lite` | confirmed | Uses the same Eventide/JUCE engine-0 patch as Temperance Pro. |
| The Him DSP Kick Ninja | `kick-ninja` | experimental | Loads but still has a white editor UI with the default experimental recipe. |
| oeksound soothe3 | `soothe3` | blocked/protected | Known protected/packed failure case; listed but not patched. |

## If your plugin is installed somewhere else

Use `--path slug=/full/path/to/binary`.

Example:

```bash
python3 juce8_megapatcher.py \
  --plugin temperance-lite \
  --path 'temperance-lite=/mnt/audio/Eventide/Temperance Lite.vst3/Contents/x86_64-win/Temperance Lite.vst3' \
  --dry-run
```

Then remove `--dry-run` to write the patch.

## Try an unknown plugin safely

Use probe mode. Probe mode never writes anything.

```bash
python3 juce8_megapatcher.py --probe '/path/to/Some Plugin.vst3/Contents/x86_64-win/Some Plugin.vst3'
```

Probe mode prints:

- SHA-256 hash
- JUCE version strings, if found
- known patch signatures that match

If probe mode finds useful matches, open an issue and paste the full output:

https://github.com/DerpcatMusic/Linux-Juce8-Patcher/issues

Do **not** use a random known recipe on an unknown plugin. Binary patch signatures are plugin-build-specific.

## Include experimental recipes

Experimental recipes are skipped unless you ask for them.

Preview everything known:

```bash
python3 juce8_megapatcher.py --dry-run --all-known
```

Patch one experimental recipe explicitly:

```bash
python3 juce8_megapatcher.py --plugin kick-ninja --dry-run
python3 juce8_megapatcher.py --plugin kick-ninja
```

Include experimental recipes in the normal full run:

```bash
python3 juce8_megapatcher.py --include-experimental --dry-run
python3 juce8_megapatcher.py --include-experimental
```

## What output means

Common statuses:

| Status | Meaning |
| --- | --- |
| `patched` | This patch would be applied, or was applied. |
| `already` | The binary already contains that patch. |
| `missing` | The expected signature was not found. |
| `error` | Something looked unsafe or ambiguous; the patcher refuses to write. |
| `blocked` | The recipe is intentionally disabled. |

If every line says `already`, the plugin was already patched.

If a dry-run says `dry-run: would write patched binary`, remove `--dry-run` to actually patch.

## Restore from backup

Every write creates a backup directory like:

```text
~/.local/share/plugin-binary-backups/juce8-megapatcher-filterverse-YYYYMMDD-HHMMSS/
```

To restore manually, close the DAW and copy the `.orig` file back over the plugin binary.

Example:

```bash
cp "$HOME/.local/share/plugin-binary-backups/juce8-megapatcher-filterverse-YYYYMMDD-HHMMSS/Filterverse.vst3.orig" \
  "$HOME/.wine/drive_c/Program Files/Common Files/VST3/Filterverse.vst3/Contents/x86_64-win/Filterverse.vst3"
```

Adjust the paths for your plugin.

## What it patches

Recipes combine targeted JUCE 8 binary patch primitives, including:

- `Component::createNewPeer(..., engine = 1)` -> `engine = 0`
- `NativeImageType` Direct2D factory fallback -> null
- `HWNDComponentPeer::setCurrentRenderingEngine()` -> renderer `0`
- JUCE renderer descriptor table rewrite:

```text
Direct2D constructor -> Software/GDI constructor
```

- an inlined `D2DRenderContext` construction block seen in Filterverse

The source also contains extra Direct2D/DirectComposition stub helpers for local experiments:

- `D3D11CreateDevice` -> `E_FAIL`
- `CreateDXGIFactory2` -> `E_FAIL`
- `DCompositionCreateDevice` -> `E_FAIL`
- `D2D1CreateFactory` -> `E_FAIL`

Those stubs are not part of the default Kick Ninja recipe because they have not fixed its white editor UI yet.

## Known notes

### Kick Ninja

Current default experimental recipe keeps the non-hanging Kick Ninja baseline:

- `createNewPeer` engine argument `1 -> 0`
- `NativeImageType` factory fallback `rsi -> null`
- renderer engine clamp to `0`
- renderer descriptor `Direct2D` constructor -> GDI constructor

Additional local experiments that did not fix the white UI or made behavior worse are intentionally not in the recipe:

- pixel-data reroutes
- `D2D1CreateFactory` no-op/disable experiments
- `DComposition` branch patching
- NativeImage global accessor nulling
- D3D11/DXGI `E_FAIL` stubs

### soothe3

soothe3 contains the same JUCE renderer descriptor strings, but the binary is protected/packed. Editing the plaintext descriptor table caused yabridge/Wine to fail during VST3 module initialization, before the editor could open. The script therefore lists soothe3 but does not patch it.
