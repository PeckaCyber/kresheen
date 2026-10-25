# PyInstaller spec for the desktop build (one folder, console app). Run through build.py, not directly.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

# include_py_files: the Alembic migrations are .py files that Alembic reads from disk, not imports.
datas = collect_data_files("kresheen", include_py_files=True)
datas += collect_data_files("docx")
datas += copy_metadata("kresheen")  # `kresheen --version` reads the installed package metadata
# Routes, ingestors and uvicorn's protocol and loop implementations are partly imported by name at run time.
hiddenimports = collect_submodules("kresheen") + collect_submodules("uvicorn")

a = Analysis(
    ["launcher.py"],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "hypothesis"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="kresheen", console=True, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, name="kresheen", upx=False)
