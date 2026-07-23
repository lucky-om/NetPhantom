# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['installer.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('dist/NetPhantom.exe', '.'),
        ('npcap_installer.exe', '.'),
        ('../../netphantom/main.py', 'netphantom'),
        ('../../netphantom/gui.py', 'netphantom'),
        ('../../netphantom/capture.py', 'netphantom'),
        ('../../netphantom/analyzer.py', 'netphantom'),
        ('../../netphantom/errors.py', 'netphantom'),
        ('../../setup.py', '.'),
        ('../../requirements.txt', '.'),
        ('../../logo.png', '.'),
        ('../../logo.ico', '.')
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
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon='../../logo.ico',
    version='version_info.txt',
    manifest='app.manifest',
)
