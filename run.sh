cd /home/auston/desenv/secp256k1fu

#!/bin/sh
#Run
./tho 24 16 2
#File watch 
while inotifywait -e modify tho.log; do
  xdg-open oba.gif
done
