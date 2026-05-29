# https://github.com/espressif/esptool/blob/master/esptool/reset.py
#  esptool --port /dev/cu.usbmodem59720648061 --before default-reset chip-id
# python -m esptool --chip esp32s3 -b 460800 --before default_reset --after hard_reset -p /dev/cu.usbmodem11101 write_flash "@flash_args"
# esptool --chip esp32s3 -b 460800 --before default_reset --after hard_reset -p /dev/cu.usbmodem59720648061  chip-id
import sys
import time

import serial

# Open the serial port (replace 'COM3' or '/dev/ttyUSB0' with your port)
print('opening port', sys.argv[1])
ser = serial.Serial(sys.argv[1], 9600,rtscts=True,dsrdtr=True)

# Set RTS to True (Asserted / logic high)
ser.rts = True

time.sleep(1)
# Set RTS to False (De-asserted / logic low)
ser.rts = False

ser.close()