#!/bin/bash

cd /github/workspace
ls -l
python3 setup.py install
pip3 install wheel
pip3 install pyinstaller
# for pyinstaller to run
pip3 uninstall jeepney -y
pip3 install jeepney
pyinstaller --onefile --clean msksidekick.py
cd /github/workspace/dist
# tail -f /dev/null
