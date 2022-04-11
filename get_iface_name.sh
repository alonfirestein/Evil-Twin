#!/bin/bash

return_iface () { return iwconfig 2>&1 | grep ESSID | sed 's/\"//g' | cut -f1  -d" " }

echo return_iface

