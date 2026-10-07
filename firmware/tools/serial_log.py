"""Reset the board over USB-Serial/JTAG and print its log for N seconds."""
import subprocess
import sys
import time

import serial

port, secs = sys.argv[1], float(sys.argv[2])
# Let esptool do the reset: its sequence boots the app on every board tried, where a plain
# RTS pulse sometimes left the chip in the ROM download mode (DTR drives GPIO0).
subprocess.run([sys.executable, "-m", "esptool", "--port", port, "--after", "hard_reset", "chip_id"],
               check=True, stdout=subprocess.DEVNULL)
# Open with DTR and RTS released, so opening the port doesn't reset the chip again.
s = serial.Serial(None, 115200, timeout=0.2)
s.port = port
s.dtr = False
s.rts = False
s.open()
end = time.time() + secs
while time.time() < end:
    data = s.read(4096)
    if data:
        sys.stdout.write(data.decode("utf-8", "replace"))
        sys.stdout.flush()
