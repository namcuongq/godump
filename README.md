# godump

GoDump.exe allows to dump the lsass process without dbghelp!MinidumpWriteDump Api. If you don't want to write file to disk, you can edit the code for transfer to other machine.
#####
GoDump.exe cannot bypass PPL protection in the system


## Usage

First, please get current PID of lsass.exe 

```
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaPid" | ft -Property LsaPid
```

```
.\godump.exe <LSASS_PID>

Ex: godump.exe 696
```
