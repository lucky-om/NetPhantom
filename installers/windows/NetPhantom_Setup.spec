# -*- mode: python ; coding: utf-8 -*-
# NetPhantom Setup Installer PyInstaller Spec
# Run AFTER building NetPhantom.spec:  pyinstaller -y --clean NetPhantom_Setup.spec

import os
SPEC_DIR = SPECPATH
ROOT = os.path.abspath(os.path.join(SPEC_DIR, '..', '..'))

a = Analysis(
    [os.path.join(SPEC_DIR, 'installer.py')],
    pathex=[],
    binaries=[],
    datas=[
        (os.path.join(SPEC_DIR, 'dist', 'NetPhantom'), 'app_files'),
        (os.path.join(ROOT, 'logo.png'), '.'),
        (os.path.join(ROOT, 'logo.ico'), '.'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetPhantom_Setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=os.path.join(ROOT, 'logo.ico'),
    version=os.path.join(SPEC_DIR, 'version_info.txt'),
    manifest=os.path.join(SPEC_DIR, 'app.manifest'),
)
