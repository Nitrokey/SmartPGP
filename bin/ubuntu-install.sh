#!/bin/bash
sudo apt install -yq `cat ubuntu-packages-requirements.txt`
pip2 install -r requirements.txt --user
