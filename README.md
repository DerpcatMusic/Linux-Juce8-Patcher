# Linux-Juce8-Patcher

Patch selected JUCE 8 Windows VST3 plugin binaries so their editor UIs avoid JUCE's Direct2D path under Wine/yabridge.

This is a binary patcher for specific plugin builds. It is intentionally conservative:

- creates timestamped backups before writing
- restores the original file mode after patching
- refuses ambiguous or unexpected byte signatures
- keeps confirmed recipes separate from experimental recipes

Close the plugin host or DAW before patching a plugin binary.

## Current recipe status

| Plugin | Slug | Status | Notes |
| --- | --- | --- | --- |
| Polyverse Filterverse | `filterverse` | confirmed | Confirmed working in Bitwig/yabridge after patching. |
| Eventide Temperance Pro | `temperance-pro` | confirmed | Confirmed working in Bitwig/yabridge after patching. |
| Eventide Temperance Lite | `temperance-lite` | confirmed | Uses the same Eventide/JUCE engine-0 patch as Temperance Pro. |
| oeksound soothe3 | `soothe3` | blocked/protected | Static descriptor-table patch caused loader/protection failure and was rolled back. |
| The Him DSP Kick Ninja | `kick-ninja` | experimental | Loads but still has a white editor UI with the default experimental recipe. |

## Usage

Dry-run confirmed recipes:

```bash
python3 juce8_megapatcher.py --dry-run
```

Patch confirmed recipes:

```bash
python3 juce8_megapatcher.py
```

Dry-run every known recipe, including experimental ones:

```bash
python3 juce8_megapatcher.py --dry-run --all-known
```

Patch one specific plugin recipe:

```bash
python3 juce8_megapatcher.py --plugin filterverse
```

Patch an experimental recipe explicitly:

```bash
python3 juce8_megapatcher.py --plugin kick-ninja
```

Override a path:

```bash
python3 juce8_megapatcher.py \
  --plugin filterverse \
  --path 'filterverse=/custom/path/Filterverse.vst3'
```

Backups are written under:

```text
~/.local/share/plugin-binary-backups/
```

The script is idempotent. If a patch is already present, it reports `already` and does not rewrite the file.

## What it patches

Recipes combine targeted JUCE 8 binary patch primitives, including:

- `Component::createNewPeer(..., engine = 1)` to `engine = 0`
- `NativeImageType` Direct2D factory fallback to null
- `HWNDComponentPeer::setCurrentRenderingEngine()` to clamp to renderer `0`
- JUCE renderer descriptor table rewrite:

```text
Direct2D constructor -> Software/GDI constructor
```

- an inlined `D2DRenderContext` construction block seen in Filterverse

The source also contains extra Direct2D/DirectComposition infrastructure stub helpers for local experiments:

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
