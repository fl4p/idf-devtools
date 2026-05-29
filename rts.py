#!/usr/bin/env python3
"""Reset an ESP32 over the USB-UART bridge's auto-reset lines (RTS->EN, DTR->IO0),
mirroring esptool's HardReset / ClassicReset.

    rts.py <port>                 # hard reset: reboot into the running app
    rts.py <port> --bootloader    # reset into ROM download (bootloader) mode

The port is opened WITHOUT hardware flow control: with rtscts/dsrdtr the OS
driver owns RTS/DTR and the manual toggles below are ignored. Boards that expose
the chip's native USB (USB-Serial-JTAG, e.g. an ESP32-S3 USB-CDC port) do not use
this classic RTS/DTR circuit — reset those with esptool, which has a dedicated
strategy.
"""
import argparse
import sys
import time

import serial  # pyserial

RESET_DELAY = 0.1


def _set_rts(ser, state):
    ser.rts = state
    ser.dtr = ser.dtr  # re-emit DTR so Windows usbser.sys sends the RTS change too


def hard_reset(ser):
    """Pulse EN low->high to reboot; IO0 stays HIGH so the app runs (not download)."""
    ser.dtr = False       # IO0 = HIGH
    _set_rts(ser, True)   # EN  = LOW  (chip in reset)
    time.sleep(RESET_DELAY)
    _set_rts(ser, False)  # EN  = HIGH (chip runs)


def bootloader_reset(ser):
    """ClassicReset: hold IO0 LOW across the EN edge to enter ROM download mode."""
    ser.dtr = False       # IO0 = HIGH
    _set_rts(ser, True)   # EN  = LOW
    time.sleep(RESET_DELAY)
    ser.dtr = True        # IO0 = LOW
    _set_rts(ser, False)  # EN  = HIGH (latches download mode)
    time.sleep(RESET_DELAY)
    ser.dtr = False       # IO0 = HIGH, done


def main():
    ap = argparse.ArgumentParser(description="Reset an ESP32 via the RTS/DTR auto-reset lines.")
    ap.add_argument("port")
    ap.add_argument("-b", "--bootloader", action="store_true",
                    help="reset into ROM download mode instead of the app")
    args = ap.parse_args()
    ser = serial.Serial(args.port, 115200, rtscts=False, dsrdtr=False)
    try:
        (bootloader_reset if args.bootloader else hard_reset)(ser)
    finally:
        ser.close()


if __name__ == "__main__":
    sys.exit(main())
