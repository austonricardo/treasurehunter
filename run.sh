cd /home/auston/desenv/treasurehunter

#!/bin/sh
#Run
./tho 24 16 2
#File watch 
while inotifywait -e modify tho.log; do
  xdg-open oba.gif
done
