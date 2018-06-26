# Glibc Malloc POCs
This repo contains a POC and a reference exploit for abusing unlinking of large chunks in Glibc's malloc implementation.

| File | Description |
| ---- | ----------- |
| [frontlink_arbitrary_allocation.c](frontlink_arbitrary_allocation.c) | Proof of concept implemented in C implementing an allocation of a small bin chunk of arbitrary size at an arbitrary address. |
| [AsisCTF18_FiftyDollars.py](AsisCTF18_FiftyDollars.py) | Exploit using the technique shown in [frontlink_arbitrary_allocation.c](frontlink_arbitrary_allocation.c) |
| fifty_dollars | Challenge binary for Asis CTF 2018's challenge [Fifty Dollars](https://ctftime.org/task/6018). |
| [run.sh](run.sh) | Script to expose the challenge on the host on port 4444. |
| libc6_2.23-0ubuntu9_amd64.so | Libc version used during the CTF |

# How to use
Take note that the POC only runs successfully on systems using libc versions that do not make use of tcaches. This means libc version <2.26 required. As of writing this you can use a current ubuntu version to run the compiled POC.

## Running the poc
```bash
gcc frontlink_arbitrary_allocation.c && ./a.out
```

## Running the sample exploit
```bash
./run.sh
```

```bash
./AsisCTF18_FiftyDollars.py
```