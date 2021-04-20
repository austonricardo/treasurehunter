#!/bin/sh
# 
while inotifywait -e modify tho.log; do
  xdg-open oba.gif
done