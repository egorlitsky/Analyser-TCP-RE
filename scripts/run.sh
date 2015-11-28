#!/bin/bash



for script in ./scripts/*.py
do
    python3 $script
done

exit 0