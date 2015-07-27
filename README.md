# Plumber
Plumber is the code-name for Project B-Hole.  ~~Project B-Hole~~Plumber is an LD_PRELOAD hooking library for [Discotech](https://github.com/the-tetanus-clinic/discotech), providing lazy initialization and hooks of connect and getaddrinfo.

## Usage
Linux/FreeBSD:
```
DISCO_CONF=/path/to/discotech.conf.json \
LD_PRELOAD=target/debug/libplumber.so \
$PROGRAM
```

OSX:
```
DISCO_CONF=/path/to/discotech.conf.json \
DYLD_INSERT_LIBRARIES=/abs/path/to/libplumber.so \
DYLD_FORCE_FLAT_NAMESPACE=YES \
$PROGRAM
```
