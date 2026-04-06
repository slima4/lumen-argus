# PyInstaller spec for lumen-argus-agent sidecar binary.
#
# Produces a single-file executable for Tauri sidecar.
# Zero C extensions — pure Python + stdlib only.
#
# Build:
#   pyinstaller packages/agent/lumen-argus-agent.spec --distpath dist --workpath build
#
# Output: dist/lumen-argus-agent
#
# For tray app, rename to arch-specific name:
#   cp dist/lumen-argus-agent src-tauri/binaries/lumen-argus-agent-aarch64-apple-darwin

import os
import sys

sys.path.insert(0, os.path.join(SPECPATH, '..', 'core'))

a = Analysis(
    [os.path.join(SPECPATH, 'lumen_argus_agent', '__main__.py')],
    pathex=[
        os.path.join(SPECPATH, '..', 'core'),
    ],
    binaries=[],
    datas=[],
    hiddenimports=[
        'lumen_argus_core',
        'lumen_argus_core.clients',
        'lumen_argus_core.detect',
        'lumen_argus_core.detect_models',
        'lumen_argus_core.mcp_configs',
        'lumen_argus_core.mcp_setup',
        'lumen_argus_core.setup_wizard',
        'lumen_argus_core.watch',
        'lumen_argus_core.time_utils',
        'lumen_argus_core.enrollment',
        'lumen_argus_core.telemetry',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'aiohttp',
        'yarl',
        'multidict',
        'aiosignal',
        'frozenlist',
        'async_timeout',
        'pyyaml',
        'yaml',
        'pyahocorasick',
        'ahocorasick',
        'crossfire',
        'sqlite3',
        'tkinter',
        'matplotlib',
        'numpy',
        'PIL',
        'unittest',
        'doctest',
        'pydoc',
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='lumen-argus-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=False,
    console=True,
    codesign_identity=os.environ.get('CODESIGN_IDENTITY', ''),
    entitlements_file=os.environ.get('ENTITLEMENTS_FILE', ''),
)
