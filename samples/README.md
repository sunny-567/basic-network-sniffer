# Sample data

`synthetic_metadata.csv` contains synthetic demonstration metadata created
from packets constructed in memory. The documentation IP addresses are examples;
these rows are not real traffic or a live capture.

Generate a fresh sample from the project root:

```powershell
python .\scripts\generate_synthetic_sample.py --output .\output\synthetic_demo.csv
```

No PCAP file is included. Use only a PCAP created in an authorized lab or a
sample whose license and permitted use you have checked.
