#!/bin/bash

cd /github/workspace
python3.8 setup.py install
#pip3 install wheel
pip3 install pyinstaller
# for pyinstaller to run
#pip3 uninstall jeepney -y
#pip3 install jeepney
# pyinstaller --onefile --clean msksidekick.py
pyinstaller --onefile --clean --hidden-import pkg_resources msksidekick.py
cd /github/workspace/dist
# tail -f /dev/null
