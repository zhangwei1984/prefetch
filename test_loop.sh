#!/bin/sh

./loop -f mnt &
loopback_pid=$!

cat /usr/share/dict/words | md5sum
cat mnt/usr/share/dict/words | md5sum
cat mnt/usr/share/dict/words | md5sum

fusermount -u $PWD/mnt
kill $loopback_pid

