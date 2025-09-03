@echo off
echo Running UnlockTool Changer...
pushd "%~dp0"
pythonw "cambiar_contrasena_unlocktool.py"
popd
:: No pause here, as the console should close immediately