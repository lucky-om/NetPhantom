import os
ROOT = os.path.abspath(os.path.join(SPECPATH, '..', '..'))

a = Analysis(
    [os.path.join(ROOT, 'netphantom', 'main.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, 'logo.png'), '.'),
        (os.path.join(ROOT, 'logo.ico'), '.'),
    ],
    hiddenimports=[
        'scapy.layers.all',
        'scapy.layers.http',
        'scapy.layers.tls',
        'scapy.layers.tls.all',
        'pywifi',
        'PIL',
        'PIL._tkinter_finder',
        'netphantom',
        'netphantom.ai_engine',
        'netphantom.analyzer',
        'netphantom.capture',
        'netphantom.errors',
        'netphantom.gui',
        'netphantom.main',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter.test', 'unittest', 'test'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetPhantom',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # console=False: GUI-only app — no CMD window flashes on launch.
    # All crashes are logged to %APPDATA%\NetPhantom\crash.log by main.py.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # uac_admin=True: Windows auto-elevates via manifest on first launch.
    uac_admin=True,
    icon=os.path.join(ROOT, 'logo.ico'),
    version=os.path.join(SPECPATH, 'version_info.txt'),
    manifest=os.path.join(SPECPATH, 'app.manifest'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='NetPhantom',
)
