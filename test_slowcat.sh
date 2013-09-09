#!/bin/sh
#target=$HOME/turnkey-mediawiki-11.3-lucid-x86-vmdk.zip
target=$HOME/5000M
#target=$HOME/500M
#target=$HOME/1000M-random
#target=/usr/share/dict/words
#target=$HOME/Kleintruth.mp3
slowcat=$HOME/code/slowcat-directio/slowcat-directio
mnt_clone=mnt
skip=0
block_size=1048576
#block_size=131072
rate=20e6

# echo Run md5sum native

echo 3 > /proc/sys/vm/drop_caches
time md5sum $target
time md5sum $target
echo
echo


# echo Run md5sum with fuse

./fusexmp_fh -f  $mnt_clone &
loopback_pid=$!
sleep 3
echo 3 > /proc/sys/vm/drop_caches
time md5sum $mnt_clone/$target
time md5sum $mnt_clone/$target
umount $mnt_clone
kill -9 $loopback_pid
echo
echo


echo Run md5sum with prefetching mcd

./mcd flush
USE_MCD=1 ./loop -s -f $mnt_clone &
loopback_pid=$!
sleep 3
echo 3 > /proc/sys/vm/drop_caches
echo Starting md5sum
time md5sum $mnt_clone/$target
tail fuse_sync_loop.log
time md5sum $mnt_clone/$target
tail fuse_sync_loop.log
umount $mnt_clone
kill -9 $loopback_pid
echo
echo

exit

echo Run md5sum with prefetching

./loop -f  $mnt_clone &
loopback_pid=$!
sleep 3
echo 3 > /proc/sys/vm/drop_caches
time md5sum $mnt_clone/$target
tail fuse_sync_loop.log
time md5sum $mnt_clone/$target
tail fuse_sync_loop.log
umount $mnt_clone
kill -9 $loopback_pid
echo
echo

exit

echo Run slowcat native

echo 3 > /proc/sys/vm/drop_caches
time $slowcat $target $rate $skip $block_size > /dev/null
time $slowcat $target $rate $skip $block_size > /dev/null
echo
echo


echo Run slowcat fusexmp_fh
./fusexmp_fh -f  $mnt_clone &
loopback_pid=$!
sleep 1
echo 3 > /proc/sys/vm/drop_caches
time $slowcat $mnt_clone/$target $rate $skip $block_size > /dev/null
time $slowcat $mnt_clone/$target $rate $skip $block_size > /dev/null
umount $mnt_clone
kill -9 $loopback_pid
echo
echo

echo Run slowcat with prefetching

./loop -f -s $mnt_clone &
loopback_pid=$!
sleep 1
echo 3 > /proc/sys/vm/drop_caches
time $slowcat $mnt_clone/$target $rate $skip $block_size > /dev/null
tail fuse_sync_loop.log
time $slowcat $mnt_clone/$target $rate $skip $block_size > /dev/null
umount $mnt_clone
tail fuse_sync_loop.log
kill -9 $loopback_pid
echo
echo

exit
