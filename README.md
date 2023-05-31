# Find Vulnerable Drivers

Find .sys files on disk and compare them against known vulnerable file hashes from https://www.loldrivers.io.

It will then print the file location, the hash and filename according to loldrivers.io, plus if the driver is running and if so the service name.

## Usage

Clone and run

```
powershell -ep bypass
. .\find-vulnerable-drivers.ps1
```

Quick usage:

```
powershell -ep bypass { iwr https://raw.githubusercontent.com/m0rv4i/find-vulnerable-drivers/master/find-vulnerable-drivers.ps1 | select -ExpandProperty content | iex }
```

## Credits

Inspired by work done by [@api0cradle / @oddvar.moe](https://gist.githubusercontent.com/api0cradle/d52832e36aaf86d443b3b9f58d20c01d/raw/94f72cf5639e006aff7a69678e84f5a868ec7e79/check_vulnerabledrivers.ps1)
