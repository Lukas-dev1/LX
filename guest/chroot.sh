# chroot: absolute paths, absolute symlinks and ".." stay inside; exec runs the chroot's own programs.
mkdir -p /j/bin /j/lib /j/etc
cp /bin/busybox /j/bin/
cp /lib/ld-musl-x86_64.so.1 /j/lib/
echo inside > /j/etc/x
ln -s /etc/x /j/link
chroot /j /bin/busybox sh -c 'cd /; cd ..; echo "pwd $(/bin/busybox pwd), x $(/bin/busybox cat /etc/x), link $(/bin/busybox cat /link), up $(/bin/busybox ls /.. | /bin/busybox tr "\n" " ")"'
