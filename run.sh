cd /home/auston/desenv/thnew

#!/bin/sh
#Run
./tho2 20 16 10 40000000000000000 7ffffffffffffffff
#File watch 
while inotifywait -e modify tho.log; do
  xdg-open oba.gif
done
