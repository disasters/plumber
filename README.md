# Plumber
Arbitrary service discovery + load balancing for legacy systems.

Plumber is an LD_PRELOAD hooking library for [Discotech](https://github.com/the-tetanus-clinic/discotech), providing lazy initialization and hooks of connect and getaddrinfo.

getaddrinfo:
  does hostname match a pattern?
    return magic IP

connect:
  is ip magic?
    perform callback fetcher

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
