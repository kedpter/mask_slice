### Mask Slice

Imagine you have 5 computers, and you want to run a mask like `?d?a?a?a?a?a?a?a`.
You will need to split the mask task into serveral parts. Normally we will assign 2 smaller masks for
each computer, and this script can help you with that. Beside, It can actually do much better since every computer will have a different speed and we may assign
more than just 2 masks for some computer and lesser for another. Another option is to distribute a 10 min task for each computer. When task is finished, the computer will request another 10 min as long as the mask keyspace is not exhausted.

The script is written to cut off a slice from a hashcat mask of huge keyspace,
and the result will be a group of masks with smaller keyspace.

It supports both python2 and python3.

#### Usage:

`mask_slice.py [-h] [-s START] mask keycount`.

`-s` to specify the start point of the mask, note: it should be consistent with the mask.

```bash
python mask_slice.py "?d?d?d" 40
# 00?d
# 01?d
# 02?d
# 03?d
python mask_slice.py "?d?d?d" 40 -s "03?d"
# 03?d
# 04?d
# 05?d
# 06?d
```

More complicated masks are also supported as long as it's compatible with hashcat. If not,
then it's a bug that needs be fixed.

```bash
python mask_slice.py "??\\,\\\\?l?d,?1???d?d?d" 1800 -s "\\,???d?d?d"
# \,???d?d?d
# \\???d?d?d
```
