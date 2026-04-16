# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for AIHound - AI Credential Scanner
Builds a single-file Windows executable.
"""

import os

# Resolve project root (parent of pyinstaller/)
# SPECPATH is set by PyInstaller to the directory containing this .spec file
project_root = os.path.dirname(SPECPATH)

# Entry point
entry_point = os.path.join(project_root, 'aihound', 'cli.py')

# Hidden imports - PyInstaller cannot detect pkgutil.iter_modules dynamic imports
hidden_imports = [
    # Core package
    'aihound',
    'aihound.core',
    'aihound.core.scanner',
    'aihound.core.platform',
    'aihound.core.redactor',
    'aihound.core.permissions',
    'aihound.core.mcp',
    # Scanners (dynamically discovered via pkgutil)
    'aihound.scanners',
    'aihound.scanners.claude_code',
    'aihound.scanners.claude_desktop',
    'aihound.scanners.github_copilot',
    'aihound.scanners.cursor',
    'aihound.scanners.continue_dev',
    'aihound.scanners.cline',
    'aihound.scanners.windsurf',
    'aihound.scanners.chatgpt',
    'aihound.scanners.openclaw',
    'aihound.scanners.ollama',
    'aihound.scanners.lm_studio',
    'aihound.scanners.amazon_q',
    'aihound.scanners.gemini',
    'aihound.scanners.envvars',
    # New scanners (v3 features)
    'aihound.scanners.aider',
    'aihound.scanners.huggingface',
    'aihound.scanners.openai_cli',
    'aihound.scanners.git_credentials',
    'aihound.scanners.ml_platforms',
    'aihound.scanners.network_exposure',
    'aihound.scanners.docker',
    'aihound.scanners.jupyter',
    'aihound.scanners.vscode_extensions',
    'aihound.scanners.browser_sessions',
    'aihound.scanners.powershell',
    # v3 watch + MCP infrastructure
    'aihound.watch',
    'aihound.notifications',
    'aihound.remediation',
    'aihound.output.watch_formatters',
    'aihound.mcp_server',
    # mcp SDK + transitive deps that PyInstaller's static analyzer misses
    'mcp',
    'mcp.server',
    'mcp.server.fastmcp',
    'mcp.server.stdio',
    'mcp.shared',
    'mcp.types',
    # Output modules
    'aihound.output',
    'aihound.output.table',
    'aihound.output.json_export',
    'aihound.output.html_report',
    # Utility modules
    'aihound.utils',
    'aihound.utils.keychain',
    'aihound.utils.credman',
    'aihound.utils.vscdb',
    # Standard/third-party libraries that may not be auto-detected
    'rich',
    'configparser',
    'sqlite3',
]

# Data files - bundle aihound.png if it exists
datas = []
icon_path = os.path.join(project_root, 'aihound.png')
if os.path.exists(icon_path):
    datas.append((icon_path, '.'))

a = Analysis(
    [entry_point],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='aihound',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
