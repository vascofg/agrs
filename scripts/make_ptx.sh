#!/bin/bash
FILES="$(find $KERNEL_DIR -name '*.cu')"
ARCH="-m$(getconf LONG_BIT)"

for f in $FILES
do
  filename=$(basename "$f")
  filename=${filename%.*}
  nvcc $ARCH -ptx $f -o $filename.ptx
done
