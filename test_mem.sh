#!/bin/sh
#target=$HOME/turnkey-mediawiki-11.3-lucid-x86-vmdk.zip
#target=$HOME/1M
target=$HOME/500M
#target=$HOME/1000M-random
#target=/usr/share/dict/words
#target=$HOME/Kleintruth.mp3
slowcat=$HOME/code/slowcat-directio/slowcat-directio
mnt_clone=mnt


echo Run md5sum with prefetching mcd

./mcd flush
USE_MCD=1 ./loop -s -f $mnt_clone &
loopback_pid=$!
sleep 3
echo 3 > /proc/sys/vm/drop_caches

cat /proc/meminfo 2>&1 | tee meminfo.0

echo Starting md5sum
time md5sum $mnt_clone/$target
tail fuse_sync_loop.log
time md5sum $mnt_clone/$target
tail fuse_sync_loop.log
umount $mnt_clone
kill -9 $loopback_pid
echo
echo

cat /proc/meminfo 2>&1 | tee meminfo.1


exit
