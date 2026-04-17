# Memory Samples

Place a memory image file named `memory.raw` in this directory before starting the demo.

## Obtaining a sample

For a realistic demo, use one of the following publicly available memory images:

* **Volatility Foundation samples**: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
* **MemLabs**: https://github.com/stuxnet999/MemLabs (CTF-style memory images)
* **Any Windows 7/10 memory dump** captured with `winpmem`, `DumpIt`, or `Magnet RAM Capture`

## Quick start with a synthetic image

If no real image is available, you can run the demo with a small synthetic approach:

```console
docker compose exec volatility-lab bash
# Inside the container, analyse /proc/kcore (Linux live memory):
python3 vol.py -f /proc/kcore linux.pslist
```

## Expected file

Place file at: `memory-samples/memory.raw` (relative to this demo directory)
