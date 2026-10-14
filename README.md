# XZZ/DZKJ Exporter by CE

![IMG](https://i.imgur.com/0rxHIVS.png)

XZZ/DZKJ Exporter is a standalone Windows program that works alongside DZKJ. It attaches to a supported DZKJ process, lets DZKJ load the document you open, and saves a decoded copy of captured PCB and PDF files.

## Requirements

- Windows 10 or later, 64-bit
- 64-bit Python 3.11 or later, with Tkinter and Frida
- The supported DZKJ installation (default path: `C:\Program Files (x86)\DZKJ\DZKJ.exe`)

## Start the program

Open PowerShell in the folder containing `xzz-dzkj_exporter.py` and run:

```powershell
py -3 -m pip install -r requirements.txt
py -3 xzz-dzkj_exporter.py
```

The XZZ/DZKJ Exporter window runs as its own program. It does not replace or patch the DZKJ executable.

1. Check the DZKJ executable path at the top of the window. Use **Browse...** if DZKJ is installed elsewhere.
2. Choose **Launch / Attach** to start DZKJ if needed and connect the exporter. Choose **Attach only** when DZKJ is already open.
3. Open a PCB, schematic, or PDF in DZKJ. DZKJ continues to load and display the document while the exporter prepares its captured copy.
4. Choose how to save the copy:
   - With **Auto-save captures (no Save As dialog)** checked, files go into the selected export folder. If a filename already exists, the exporter creates a unique filename.
   - With it unchecked, a **Save As** dialog opens for each captured file. The export folder is the dialog starting location.
5. Select **Detach** to stop watching the DZKJ process. Closing the exporter also detaches it.

The default export folder is the `exports` folder beside the program. Change it in the **Export folder** field or with **Browse...**. The folder is used for auto-save and as the initial location for Save As.

## Supported DZKJ build

The exporter checks the DZKJ executable before attaching. The currently supported executable has SHA-256:

```
bb765b6fb142cb048717a4a5a3b50de0b795314f2c916807453d8507cd25194d
```

Other builds are rejected because their internal document handling may differ. If attachment is denied, run the exporter with the same Windows account and permission level as DZKJ; administrator rights may be needed in some setups.

Newer builds might be supported so change the hash in the INI file to attempt an attachment. This project will not update to suit DZKJ updates.

## Configuration

The program reads `config.ini` beside `xzz-dzkj_exporter.py` when it starts. The supplied file sets the default DZKJ executable, the Frida agent file, and the supported executable SHA-256:

```ini
[DZKJ]
DZKJ_PATH=C:\Program Files (x86)\DZKJ\DZKJ.exe

[Exporter]
AGENT_PATH=agent.js
EXPECTED_SHA256=bb765b6fb142cb048717a4a5a3b50de0b795314f2c916807453d8507cd25194d
```

Relative `AGENT_PATH` values are resolved from the program folder. Use an absolute path if the agent file is stored elsewhere. The DZKJ path can also be changed in the window or overridden with `--exe`.

## Command-line use

The desktop window is the normal way to use the exporter. The command-line interface is also available:

```powershell
# Check whether a DZKJ executable is supported
py -3 xzz-dzkj_exporter.py check --exe "C:\Program Files (x86)\DZKJ\DZKJ.exe"

# Capture with automatic saving to the chosen folder
py -3 xzz-dzkj_exporter.py capture --output ".\exports"

# Attach to an already-running DZKJ process
py -3 xzz-dzkj_exporter.py capture --attach-only --output ".\exports"

# Show all commands and options
py -3 xzz-dzkj_exporter.py --help
```

Command-line capture saves automatically and stays active until you press **Ctrl+C**. PCB recovery is available for a captured wire-format PCB file:

```powershell
py -3 xzz-dzkj_exporter.py repair input.pcb output.pcb
```

## Troubleshooting

- **Unsupported DZKJ executable:** confirm that the selected path points to the supported build shown above.
- **Attach failed:** make sure DZKJ is running if you chose **Attach only**. If access is denied, run both programs at the same Windows permission level or try starting the exporter as administrator.
- **Save As appears:** uncheck **Auto-save captures (no Save As dialog)** to choose a destination for each capture. Check it to save automatically to the selected export folder.
- **PCB decode failed:** enable **Keep raw files if PCB decoding fails** before capturing again. The raw capture can help diagnose an unsupported or malformed file.
