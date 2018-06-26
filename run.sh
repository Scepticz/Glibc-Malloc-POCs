#!/bin/bash
socat tcp-listen:4444,reuseaddr,fork exec:'./preload_exec.sh'