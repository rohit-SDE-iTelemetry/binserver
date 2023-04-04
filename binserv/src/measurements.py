import utils

import time
import struct
import crcmod.predefined

DATA_START_BYTE = b"\x1b"

HEADER_SIZE = 16

VALUE_SIZE = 4
VALUE_NAN = b"\x07\x00\x00\x80"

INFO_SDI12_NR_READINGS = 20

# Convert to big endian and add to CRC total.
def update_crc(crc_tot, buf):
  calcbuf = b""
  for i in range(0, len(buf), 4):
    calcbuf += int.from_bytes(buf[i:i+4], byteorder="little", signed=False).to_bytes(4, byteorder="big", signed=False)
  crc_tot.update(calcbuf)
  return calcbuf

def parse(peer, data):
  measurements = []
  data_len = len(data)

  # Find first measurement
  start_byte = data.find(DATA_START_BYTE)
  while start_byte > -1:
    # Initialize CRC check
    crc_tot = crcmod.predefined.Crc("crc-32-mpeg")
    received_crc = 0x0000

    # Check if there is room for header.
    if data_len - start_byte >= HEADER_SIZE:
      # Ignore the received CRC when calculating own CRC.
      update_crc(crc_tot, data[start_byte:start_byte+4])
      update_crc(crc_tot, data[start_byte+8:start_byte+8+8])

      header, nr_values, reserved, received_crc, timestamp, number = struct.unpack("<BBBLLL", data[start_byte+1:start_byte+HEADER_SIZE])

      # Read header
      ntp_synced = (header & 1) > 0
      low_bat = (header & 2) > 0
      info_rec = (header & 4) > 0
      start_values = start_byte + HEADER_SIZE

      # Log
      if info_rec > 0:
        utils.log(f"{peer} + Info record at position {start_byte}", priority="debug")
      else:
        utils.log(f"{peer} + Measurement at position {start_byte}", priority="debug")
      utils.log(f"{peer} + \tNumber: %d" % number, priority="debug")
      utils.log(f"{peer} + \tTime: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(timestamp))), priority="debug")
      utils.log(f"{peer} + \tNTP synced: {ntp_synced}", priority="debug")
      utils.log(f"{peer} + \tLow battery: {low_bat}", priority="debug")
      utils.log(f"{peer} + \tNumber of values: {nr_values}", priority="debug")

      if data_len - start_values >= (nr_values * VALUE_SIZE):
        # Calculate CRC
        for i in range(0, nr_values):
          start = start_values + i * VALUE_SIZE
          end = start_values + i * VALUE_SIZE + VALUE_SIZE
          raw_val = data[start:end]
          update_crc(crc_tot, raw_val)

        crc = crc_tot.crcValue & 0xffffffff
        if crc == received_crc:
          utils.log(f"{peer} + \tCRC: valid", priority="debug")
        else:
          utils.log(f"{peer} + \tCRC: invalid", priority="debug")
          break

        if info_rec == 0:
          # Parse measurement
          values = []

          for i in range(0, nr_values):
            raw_val = data[start_values+i*VALUE_SIZE:start_values+i*VALUE_SIZE+VALUE_SIZE]
            if raw_val == VALUE_NAN:
              value = "nan"
            else:
              value, = struct.unpack("<l", raw_val)
              # Convert to floating point: last 3 bits represent number of digits after decimal point.
              dec = 7 & value
              value >>= 3
              value /= 10 ** dec
              value = "%.*f" % (dec, value)

            values.append(value)

            utils.log(f"{peer} + \tValue {i}: {value}", priority="debug")

          measurements.append({ "ntp_synced": ntp_synced, "low_bat": low_bat, "info_rec": info_rec, "time": timestamp, "number": number, "values": values })
        else:
          # Parse info record
          values = []
          sb = start_values

          counter, = struct.unpack("<B", data[sb:sb+1])
          counter = (counter & 1) > 0
          if counter:
            values.append("counter")

          anabat, extana, = struct.unpack("<BB", data[sb:sb+2])

          sb += VALUE_SIZE
          nr_sdi12_devices = int((nr_values * VALUE_SIZE - VALUE_SIZE) / (3 + VALUE_SIZE))
          for i in range(0, nr_sdi12_devices):
            sdi12_address = data[sb+i:sb+i+1].decode(errors="ignore")
            sdi12_command = data[sb+i+nr_sdi12_devices:sb+i+nr_sdi12_devices+1].decode(errors="ignore")
            sdi12_command_nr, = struct.unpack("<B", data[sb+i+nr_sdi12_devices*2:sb+i+nr_sdi12_devices*2+1])
            sdi12_readings, = struct.unpack("<I", data[sb+i*VALUE_SIZE+nr_sdi12_devices*3:sb+i*VALUE_SIZE+nr_sdi12_devices*3+VALUE_SIZE])

            nr_readings = 0
            for j in range(0, INFO_SDI12_NR_READINGS):
              if sdi12_readings & (1 << j) > 0:
                nr_readings += 1

            if nr_readings > 0:
              values.append(f"sdi12 {sdi12_address}{sdi12_command}{sdi12_command_nr} {nr_readings}")

          if (anabat & 2) > 0:
            values.append("ain1")
          if (anabat & 4) > 0:
            values.append("ain2")
          for i in range(0, 8):
            if (extana & (2**i)) > 0:
              values.append(f"eain{i+1}")
          if (anabat & 8) > 0:
            values.append("battery")

          measurements.append({ "ntp_synced": ntp_synced, "low_bat": low_bat, "info_rec": info_rec, "time": timestamp, "number": -1 * number, "values": values })
      if data_len - start_values > (nr_values * VALUE_SIZE):
        start_byte = data.find(DATA_START_BYTE, start_values + (nr_values * VALUE_SIZE))
      else:
        break
    else:
      break

  return measurements
