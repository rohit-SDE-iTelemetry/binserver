import utils
import protocol
import measurements

import sys, getopt, os
import signal
import time
import random
import ssl
import asyncio # https://docs.python.org/3/library/asyncio.html
import aiofiles # https://github.com/Tinche/aiofiles
import crcmod.predefined

VERSION = 1.07
ADATA_TIME_FORMAT = '"%Y-%m-%d %H:%M:%S"'
ADATA_NEW_FILE_TIME_FORMAT = "%Y%m%d%H%M%S"
# The first 4 bytes of a firmware file are used for the file size.
FIRMWARE_FILESIZE_OFFSET = 4

DEBUG_RANDOM_BADCRC = False
DEBUG_RANDOM_BADCRC_PROBABILITY = 40

crc32_func = crcmod.predefined.mkCrcFun("crc-32-mpeg")

async def data_last_timestamp(kidl_config, filename):
  data_directory = kidl_config["DataDirectory"]
  file_path = utils.secure_file_path(data_directory, filename)
  last_timestamp = -1

  if file_path != False and os.path.isfile(file_path):
    try:
      async with aiofiles.open(file_path, mode="r") as f:
        last_timestamp_str = await f.readline()
        last_timestamp = int(last_timestamp_str)
    except Exception as e:
      utils.log(f"- Error reading file: {e}")
      return False
  else:
    return False

  return last_timestamp

async def save_data(kidl_config, filename, data, mode="a"):
  data_directory = kidl_config["DataDirectory"]
  file_path = utils.secure_file_path(data_directory, filename)

  if file_path != False:
    try:
      async with aiofiles.open(file_path, mode=mode) as f:
        await f.write(data)
    except Exception as e:
      utils.log(f"- Error writing to file: {e}")
      return False
  else:
    return False

  return True

async def read_frame(ctx):
  crc = crcmod.predefined.Crc("crc-32-mpeg")
  frame = {
    "type": None,
    "data": None,
  }

  # Read frame and verify CRC.
  try:
    start_byte = None
    while start_byte != protocol.START_BYTE:
      start_byte = await ctx["reader"].readexactly(1)
    crc.update(start_byte)

    frame_type = await ctx["reader"].readexactly(1)
    crc.update(frame_type)

    data_bytes = data_content = b""
    if frame_type in ( protocol.FRAME_TYPE_CONF_CHECK ):
      pass
    elif frame_type in ( protocol.FRAME_TYPE_ACK,
                         protocol.FRAME_TYPE_NACK,
                         protocol.FRAME_TYPE_TIME_REQ,
                         protocol.FRAME_TYPE_CLOSE ):
      data_bytes = await ctx["reader"].readexactly(1)
    elif frame_type in ( protocol.FRAME_TYPE_FIRMW_RESUME ):
      data_content = await ctx["reader"].readexactly(10)
      data_bytes = data_content
    elif frame_type in ( protocol.FRAME_TYPE_ID,
                         protocol.FRAME_TYPE_FIRMW_CHECK,
                         protocol.FRAME_TYPE_FIRMW_CHECK2 ):
      data_len = await ctx["reader"].readexactly(1)
      data_content = await ctx["reader"].readexactly(int.from_bytes(data_len, byteorder="little", signed=False))
      data_bytes = data_len + data_content
    elif frame_type in ( protocol.FRAME_TYPE_MEASDATA,
                         protocol.FRAME_TYPE_INFO_DATA,
                         protocol.FRAME_TYPE_SETTINGS_DATA ):
      data_len = await ctx["reader"].readexactly(2)
      data_content = await ctx["reader"].readexactly(int.from_bytes(data_len, byteorder="little", signed=False))
      data_bytes = data_len + data_content
    else:
      utils.log(f"{ctx['peer']} - Unknown frame type: {frame_type}")
      return False
    crc.update(data_bytes)

    received_crc_value = await ctx["reader"].readexactly(4)

    end_byte = await ctx["reader"].readexactly(1)
    crc.update(end_byte)

    crc_value = (0xffffffff & crc.crcValue).to_bytes(4, byteorder="little", signed=False)
    if crc_value != received_crc_value or (DEBUG_RANDOM_BADCRC and random.random() < DEBUG_RANDOM_BADCRC_PROBABILITY / 100.0):
      utils.log(f"{ctx['peer']} < Frame type {frame_type} with bad CRC {crc_value} != {received_crc_value}")
      return False
  except asyncio.IncompleteReadError:
    utils.log(f"{ctx['peer']} - Incomplete read on socket")
    return None

  frame["type"] = frame_type
  frame["data"] = data_content

  return frame

async def write_frame(ctx, frame_type, data):
  # Append length of data for some frame types.
  if frame_type in ( protocol.FRAME_TYPE_FIRMW_DATA ):
    data = len(data).to_bytes(2, byteorder="little", signed=False) + data
  elif frame_type in ( protocol.FRAME_TYPE_CONF_DATA ):
    data = len(data).to_bytes(1, byteorder="little", signed=False) + data

  #import binascii
  #print(binascii.hexlify(data))

  crc = crcmod.predefined.Crc("crc-32-mpeg")
  crc.update(protocol.START_BYTE + frame_type + data + protocol.END_BYTE)
  if DEBUG_RANDOM_BADCRC and random.random() < DEBUG_RANDOM_BADCRC_PROBABILITY / 100.0:
    crc.update(b"LOWIEGIE")
  crc_value = (0xffffffff & crc.crcValue).to_bytes(4, byteorder="little", signed=False)
  ctx["writer"].write(protocol.START_BYTE + frame_type + data + crc_value + protocol.END_BYTE)
  await ctx["writer"].drain()

async def handle_frame(ctx, frame):
  if frame["type"] == protocol.FRAME_TYPE_ID:
    utils.log(f"{ctx['peer']} < ID")

    data_content = frame["data"].split(b'\r')

    if len(data_content) > 1:
      k_id = ''
      k_imei = ''
      try:
        k_id = data_content[0].decode()
        k_imei = data_content[1].decode()
      except Exception as e:
        utils.log(f"{ctx['peer']} - Decoding error: {e}")
        utils.log(f"{ctx['peer']} > NACK (NONE)")
        await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
        return True

      if k_id in config.sections():
        imei = config[k_id]["IMEI"]

        if imei == "any" or imei == k_imei:
          ctx["authenticated"] = True
          ctx["id"] = k_id
          ctx["imei"] = k_imei
          utils.log(f"{ctx['peer']} + KIDL ID: " + ctx["id"])
          utils.log(f"{ctx['peer']} + KIDL IMEI: " + ctx["imei"], priority="debug")
          utils.log(f"{ctx['peer']} > ACK")
          await write_frame(ctx, protocol.FRAME_TYPE_ACK, protocol.ACK_NONE)
          ctx["peer"] = ctx["id"]

          data_new_file = config[k_id]["DataNewFile"].lower() == "yes"
          if data_new_file:
            datestr = time.strftime(ADATA_NEW_FILE_TIME_FORMAT)
            ctx["data_file"] = f"{k_id}_{datestr}.adata"
          else:
            ctx["data_file"] = f"{k_id}.adata"
        else:
          utils.log(f"{ctx['peer']} - Wrong IMEI {imei} != {k_imei}")
          utils.log(f"{ctx['peer']} > NACK (ID_UNKNOWN)")
          await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_ID_UNKNOWN)
      else:
        utils.log(f"{ctx['peer']} > NACK (ID_UNKNOWN)")
        await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_ID_UNKNOWN)
    else:
      utils.log(f"{ctx['peer']} > NACK (NONE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
  elif not ctx["authenticated"]:
    utils.log(f"{ctx['peer']} - Ignoring unauthenticated frame")
    utils.log(f"{ctx['peer']} > NACK (NONE)")
    await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
  elif frame["type"] == protocol.FRAME_TYPE_MEASDATA:
    utils.log(f"{ctx['peer']} < MEASDATA")
    msmts = measurements.parse(ctx["peer"], frame["data"])

    data_format = config[ctx["id"]]["DataFormat"].lower()
    data_ignore_old = config[ctx["id"]]["DataIgnoreOld"].lower() == "yes"
    data_write_info_records = config[ctx["id"]]["DataWriteInfoRecords"].lower() == "yes"

    if data_format == "adata":
      new_last_timestamp = -1

      if data_ignore_old:
        last_timestamp = await data_last_timestamp(config[ctx["id"]], ctx["id"] + ".last_timestamp")
        if last_timestamp:
          utils.log(f"{ctx['peer']} - Last timestamp: {last_timestamp}")

      datastr = ""
      for msmt in msmts:
        if data_ignore_old and last_timestamp != False and msmt['time'] <= last_timestamp:
          utils.log(f"{ctx['peer']} - Ignoring measurement #{msmt['number']} with old timestamp {msmt['time']}")
        elif msmt["info_rec"] == 0 or data_write_info_records:
          # The same timestamp is used for the measurement after an info record, so never update the last timestamp with info records.
          if msmt["info_rec"] == 0:
            new_last_timestamp = msmt['time']
          timestr = time.strftime(ADATA_TIME_FORMAT, time.gmtime(float(msmt['time'])))
          vals = ""
          for val in msmt["values"]:
            vals += f"{val},"
          datastr += f"{timestr},{msmt['number']},{vals}"
          if msmt["info_rec"] == 0:
            datastr += "0\n"
          else:
            datastr += "status\n"

      save_success = await save_data(config[ctx["id"]], ctx["data_file"], datastr, mode="a")
      if save_success:
        utils.log(f"{ctx['peer']} > ACK")
        await write_frame(ctx, protocol.FRAME_TYPE_ACK, protocol.ACK_NONE)

        if new_last_timestamp > -1:
          await save_data(config[ctx["id"]], ctx["id"] + ".last_timestamp", str(new_last_timestamp), mode="w")
      else:
        utils.log(f"{ctx['peer']} > NACK (NONE)")
        await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
    else:
      utils.log(f"{ctx['peer']} - Unknown data format")
      utils.log(f"{ctx['peer']} > NACK (NONE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
  elif frame["type"] == protocol.FRAME_TYPE_TIME_REQ:
    utils.log(f"{ctx['peer']} < TIME_REQ")
    current_time = int(time.time())
    utils.log(f"{ctx['peer']} > TIME_CONFIRM")
    await write_frame(ctx, protocol.FRAME_TYPE_TIME_CONFIRM, current_time.to_bytes(4, byteorder="little", signed=False))
    utils.log(f"{ctx['peer']} + Timestamp: {current_time}", priority="debug")
  elif frame["type"] in ( protocol.FRAME_TYPE_FIRMW_CHECK, protocol.FRAME_TYPE_FIRMW_CHECK2, protocol.FRAME_TYPE_FIRMW_RESUME ):
    if frame["type"] == protocol.FRAME_TYPE_FIRMW_CHECK:
      utils.log(f"{ctx['peer']} < FIRMW_CHECK")
    elif frame["type"] == protocol.FRAME_TYPE_FIRMW_CHECK2:
      utils.log(f"{ctx['peer']} < FIRMW_CHECK2")
    else:
      utils.log(f"{ctx['peer']} < FIRMW_RESUME")

    current_firmware = config[ctx["id"]]["FirmwareVersion"]
    try:
      current_version = int(current_firmware, 16)
    except Exception as e:
      utils.log(f"{ctx['peer']} - Invalid firmware version: {e}")
      utils.log(f"{ctx['peer']} > NACK (NONE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
      return True
    firmware_file_path = os.path.join(config[ctx["id"]]["FirmwareDirectory"], "KIDL." + current_firmware)
    send_firmware = False

    if len(frame["data"]) >= 6:
      ctx["firmware_frame_length"] = int.from_bytes(frame["data"][-2:], byteorder="little", signed=False)

      # Make sure the length is a multiple of 4 and substract 4 bytes used by the position.
      ctx["firmware_frame_length"] &= 0xfffffffc
      ctx["firmware_frame_length"] -= 4

      if ctx["firmware_frame_length"] < protocol.MIN_FIRMWARE_FRAME_LENGTH or ctx["firmware_frame_length"] > protocol.MAX_FIRMWARE_FRAME_LENGTH:
        utils.log(f"{ctx['peer']} - Invalid firmware frame length: {ctx['firmware_frame_length']}")
        utils.log(f"{ctx['peer']} > NACK (NONE)")
        await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
        return True

      utils.log(f"{ctx['peer']} + Frame length: {ctx['firmware_frame_length']}", priority="debug")

      if frame["type"] == protocol.FRAME_TYPE_FIRMW_RESUME:
        request_version = int.from_bytes(frame["data"][:4], byteorder="little", signed=False)
        if request_version == current_version:
          send_firmware = True
        else:
          utils.log(f"{ctx['peer']} - Requested version ({request_version:08x}) does not match with current version ({current_version:08x})")
      else:
        data_content = frame["data"][:-2].split(b'\r')
        if len(data_content) > 1:
          try:
            hw_version = data_content[0].decode()
            fw_version = data_content[1].decode()
            if current_firmware != fw_version:
              send_firmware = True
          except Exception as e:
            utils.log(f"{ctx['peer']} - Decoding error: {e}")
            utils.log(f"{ctx['peer']} > NACK (NONE)")
            await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
            return True

          utils.log(f"{ctx['peer']} + Hardware version: {hw_version}", priority="debug")
          utils.log(f"{ctx['peer']} + Firmware version: {fw_version}", priority="debug")
        else:
          utils.log(f"{ctx['peer']} - Invalid frame content")
          utils.log(f"{ctx['peer']} > NACK (NONE)")
          await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
          return True
    else:
      utils.log(f"{ctx['peer']} - Invalid frame length")
      utils.log(f"{ctx['peer']} > NACK (NONE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
      return True

    if not send_firmware or not os.path.isfile(firmware_file_path):
      utils.log(f"{ctx['peer']} > NACK (NO_FIRMWARE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NO_FIRMWARE)
      return True

    ctx["firmware_file_data"] = b''
    try:
      async with aiofiles.open(firmware_file_path, mode="rb") as f:
        ctx["firmware_file_data"] = await f.read()
    except Exception as e:
      utils.log(f"{ctx['peer']} - Error reading firmware file: {e}")

    if len(ctx["firmware_file_data"]) > 3:
      utils.log(f"{ctx['peer']} - New version ({current_firmware}) found, entering firmware mode")
      ctx["firmware_mode"] = True
      ctx["firmware_sending_data"] = False
      ctx["firmware_attempt"] = 0
      if frame["type"] == protocol.FRAME_TYPE_FIRMW_RESUME:
        ctx["firmware_offset"] = int.from_bytes(frame["data"][4:8], byteorder="little", signed=False)
        utils.log(f"{ctx['peer']} - Skipping {ctx['firmware_offset']} bytes")
      else:
        ctx["firmware_offset"] = 0
      if frame["type"] in ( protocol.FRAME_TYPE_FIRMW_CHECK2, protocol.FRAME_TYPE_FIRMW_RESUME ):
        utils.log(f"{ctx['peer']} > FIRMW_AVAIL2")
        await write_frame(ctx, protocol.FRAME_TYPE_FIRMW_AVAIL2, ctx["firmware_file_data"][0:FIRMWARE_FILESIZE_OFFSET] + current_version.to_bytes(4, byteorder="little", signed=False))
      else:
        utils.log(f"{ctx['peer']} > FIRMW_AVAIL")
        await write_frame(ctx, protocol.FRAME_TYPE_FIRMW_AVAIL, ctx["firmware_file_data"][0:FIRMWARE_FILESIZE_OFFSET])
    else:
      utils.log(f"{ctx['peer']} - Invalid firmware file")
      utils.log(f"{ctx['peer']} > NACK (NO_FIRMWARE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NO_FIRMWARE)
  elif frame["type"] == protocol.FRAME_TYPE_CONF_CHECK:
    utils.log(f"{ctx['peer']} < CONF_CHECK")

    conf_file_path = os.path.join(config[ctx["id"]]["ConfDirectory"], ctx["id"] + ".conf")

    if not os.path.isfile(conf_file_path):
      utils.log(f"{ctx['peer']} > NACK (NO_CONF)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NO_CONF)
    else:
      ctx["conf_file_path"] = conf_file_path
      ctx["conf_file_data"] = []
      try:
        async with aiofiles.open(conf_file_path, mode="rb") as f:
          ctx["conf_file_data"] = await f.readlines()
      except Exception as e:
        utils.log(f"{ctx['peer']} - Error reading conf file: {e}")

      if len(ctx["conf_file_data"]) > 0:
        utils.log(f"{ctx['peer']} - New conf found, entering conf mode")
        ctx["conf_mode"] = True
        ctx["conf_attempt"] = 0
        ctx["conf_data"] = ctx["conf_file_data"].pop(0).strip()
        utils.log(f"{ctx['peer']} > CONF_DATA")
        utils.log(f"{ctx['peer']} + {ctx['conf_data']}", priority="debug")
        await write_frame(ctx, protocol.FRAME_TYPE_CONF_DATA, ctx["conf_data"])
      else:
        utils.log(f"{ctx['peer']} - Invalid conf file")
        utils.log(f"{ctx['peer']} > NACK (NO_CONF)")
        await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NO_CONF)
  elif frame["type"] == protocol.FRAME_TYPE_INFO_DATA:
    utils.log(f"{ctx['peer']} < INFO_DATA")
    success = await save_data(config[ctx["id"]], ctx["id"] + ".info", frame["data"], mode="wb")
    if success:
      utils.log(f"{ctx['peer']} > ACK")
      await write_frame(ctx, protocol.FRAME_TYPE_ACK, protocol.ACK_NONE)
    else:
      utils.log(f"{ctx['peer']} > NACK (NONE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
  elif frame["type"] == protocol.FRAME_TYPE_SETTINGS_DATA:
    utils.log(f"{ctx['peer']} < SETTINGS_DATA")
    success = await save_data(config[ctx["id"]], ctx["id"] + ".settings", frame["data"], mode="wb")
    if success:
      utils.log(f"{ctx['peer']} > ACK")
      await write_frame(ctx, protocol.FRAME_TYPE_ACK, protocol.ACK_NONE)
    else:
      utils.log(f"{ctx['peer']} > NACK (NONE)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NONE)
  elif frame["type"] == protocol.FRAME_TYPE_CLOSE:
    utils.log(f"{ctx['peer']} < CLOSE")
    utils.log(f"{ctx['peer']} > ACK")
    await write_frame(ctx, protocol.FRAME_TYPE_ACK, protocol.ACK_NONE)
    return False
  else:
    utils.log(f"{ctx['peer']} - Ignoring unknown frame type")

  return True

async def handle_firmware_upload(ctx, frame):
  def leave_firmware_mode():
    ctx["firmware_mode"] = False
    ctx["firmware_file_data"] = b''
    ctx["firmware_data"] = b''

  if frame["type"] == protocol.FRAME_TYPE_ACK:
    utils.log(f"{ctx['peer']} < ACK")

    ctx["firmware_attempt"] = 0

    if ctx["firmware_sending_data"]:
      ctx["firmware_offset"] += ctx["firmware_frame_length"]
    else:
      ctx["firmware_sending_data"] = True

    start = FIRMWARE_FILESIZE_OFFSET + ctx["firmware_offset"]
    end = start + ctx["firmware_frame_length"]
    ctx["firmware_data"] = ctx["firmware_file_data"][start:end]
    if ctx["firmware_data"]:
      utils.log(f"{ctx['peer']} > FIRMW_DATA")
      utils.log(f"{ctx['peer']} + OFFSET: {ctx['firmware_offset']}", priority="debug")
      await write_frame(ctx, protocol.FRAME_TYPE_FIRMW_DATA, ctx["firmware_offset"].to_bytes(4, byteorder="little", signed=False) + ctx["firmware_data"])
    else:
      utils.log(f"{ctx['peer']} - End of firmware data, leaving firmware mode")
      leave_firmware_mode()
  elif frame["type"] == protocol.FRAME_TYPE_NACK:
    utils.log(f"{ctx['peer']} < NACK")

    ctx["firmware_attempt"] += 1

    if ctx["firmware_attempt"] >= protocol.MAX_ATTEMPTS:
      utils.log(f"{ctx['peer']} - Maximum attempts reached, leaving firmware mode")
      leave_firmware_mode()
    elif not ctx["firmware_sending_data"]:
      utils.log(f"{ctx['peer']} > FIRMW_AVAIL")
      await write_frame(ctx, protocol.FRAME_TYPE_FIRMW_AVAIL, ctx["firmware_file_data"][0:FIRMWARE_FILESIZE_OFFSET])
    else:
      utils.log(f"{ctx['peer']} > FIRMW_DATA")
      utils.log(f"{ctx['peer']} + OFFSET: {ctx['firmware_offset']}", priority="debug")
      await write_frame(ctx, protocol.FRAME_TYPE_FIRMW_DATA, ctx["firmware_offset"].to_bytes(4, byteorder="little", signed=False) + ctx["firmware_data"])
  else:
    utils.log(f"{ctx['peer']} - Unexpected frame type, leaving firmware mode")
    leave_firmware_mode()
    return await handle_frame(ctx, frame)

  return True

async def handle_conf_upload(ctx, frame):
  def leave_conf_mode():
    ctx["conf_mode"] = False
    ctx["conf_file_path"] = ''
    ctx["conf_file_data"] = []
    ctx["conf_data"] = b''

  if frame["type"] == protocol.FRAME_TYPE_ACK:
    utils.log(f"{ctx['peer']} < ACK")

    ctx["conf_attempt"] = 0

    if len(ctx["conf_file_data"]) > 0:
      ctx["conf_data"] = ctx["conf_file_data"].pop(0).strip()
    else:
      ctx["conf_data"] = b''

    # Move conf file is there is no more data (on end of conf_file_data or the data is empty after the strip above).
    if len(ctx["conf_data"]) == 0:
      timestamp = str(int(time.time()))
      try:
        os.rename(ctx["conf_file_path"], ctx["conf_file_path"] + "." + timestamp)
      except Exception as e:
        utils.log(f"{ctx['peer']} - Error moving conf file: {e}")
  elif frame["type"] == protocol.FRAME_TYPE_NACK:
    utils.log(f"{ctx['peer']} < NACK")

    ctx["conf_attempt"] += 1

    if ctx["conf_attempt"] >= protocol.MAX_ATTEMPTS:
      utils.log(f"{ctx['peer']} - Maximum attempts reached, leaving conf mode")
      leave_conf_mode()
    else:
      utils.log(f"{ctx['peer']} > CONF_DATA")
      utils.log(f"{ctx['peer']} + {ctx['conf_data']}", priority="debug")
      await write_frame(ctx, protocol.FRAME_TYPE_CONF_DATA, ctx["conf_data"])
  elif frame["type"] == protocol.FRAME_TYPE_CONF_CHECK:
    utils.log(f"{ctx['peer']} < CONF_CHECK")

    if len(ctx["conf_data"]) > 0:
      utils.log(f"{ctx['peer']} > CONF_DATA")
      utils.log(f"{ctx['peer']} + {ctx['conf_data']}", priority="debug")
      await write_frame(ctx, protocol.FRAME_TYPE_CONF_DATA, ctx["conf_data"])
    else:
      utils.log(f"{ctx['peer']} - End of conf data, leaving conf mode")
      leave_conf_mode()

      utils.log(f"{ctx['peer']} > NACK (NO_CONF)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_NO_CONF)
  else:
    utils.log(f"{ctx['peer']} - Unexpected frame type, leaving conf mode")
    leave_conf_mode()
    return await handle_frame(ctx, frame)

  return True

async def handle_client(reader, writer):
  ctx = {}

  ctx["reader"] = reader
  ctx["writer"] = writer
  ctx["peer_ip"] = writer.get_extra_info("peername")[0]
  ctx["peer"] = ctx["peer_ip"]
  ctx["tls_cipher"] = writer.get_extra_info("cipher")
  ctx["read_attempt"] = 0

  ctx["authenticated"] = False
  ctx["id"] = None
  ctx["imei"] = None

  ctx["firmware_mode"] = False
  ctx["firmware_frame_length"] = 4
  ctx["firmware_sending_data"] = False
  ctx["firmware_attempt"] = 0
  ctx["firmware_file_data"] = b''
  ctx["firmware_offset"] = 4
  ctx["firmware_data"] = b''

  ctx["conf_mode"] = False
  ctx["conf_attempt"] = 0
  ctx["conf_file_path"] = ''
  ctx["conf_file_data"] = []
  ctx["conf_data"] = b''

  if ctx["tls_cipher"]:
    utils.log(f"{ctx['peer']} - Accepted TLS connection: {ctx['tls_cipher']}")
  else:
    utils.log(f"{ctx['peer']} - Accepted connection")
  while True:
    try:
      frame = await asyncio.wait_for(read_frame(ctx), timeout=protocol.TIMEOUT)
    except asyncio.TimeoutError:
      utils.log(f"{ctx['peer']} - Read timeout")
      ctx["read_attempt"] += 1
      if ctx["read_attempt"] >= protocol.MAX_ATTEMPTS:
        break
      continue
    except Exception as e:
      utils.log(f"{ctx['peer']} - Socket read error: {e}")
      break

    if frame == None:
      utils.log(f"{ctx['peer']} - Connection closed by client")
      break

    if frame == False:
      utils.log(f"{ctx['peer']} > NACK (BADCRC)")
      await write_frame(ctx, protocol.FRAME_TYPE_NACK, protocol.NACK_BADCRC)
      ctx["read_attempt"] += 1
      if ctx["read_attempt"] >= protocol.MAX_ATTEMPTS:
        break
      continue

    ctx["read_attempt"] = 0

    keep_socket_open = True
    if ctx["firmware_mode"]:
      keep_socket_open = await handle_firmware_upload(ctx, frame)
    elif ctx["conf_mode"]:
      keep_socket_open = await handle_conf_upload(ctx, frame)
    else:
      keep_socket_open = await handle_frame(ctx, frame)
    if not keep_socket_open:
      break

  utils.log(f"{ctx['peer']} - Closing connection")
  writer.close()

async def signal_server(signal):
  if signal == signal.SIGHUP:
    utils.log(f"Recevied reload signal {signal.name}")
    new_config = utils.parse_config(conf_file)

    if not new_config:
      utils.log("Ignoring new config file")
    else:
      utils.log("Loading new config file")
      global config
      config = new_config
  else:
    utils.log(f"Received exit signal {signal.name}")
    for t in asyncio.all_tasks():
      if t is not asyncio.current_task():
        t.cancel()

async def start_server(bind_ip, port, tls_port):
  if os.name != "nt":
    loop = asyncio.get_event_loop()
    signals = ( signal.SIGHUP, signal.SIGTERM, signal.SIGINT )
    for s in signals:
      loop.add_signal_handler(s, lambda s=s: asyncio.create_task(signal_server(s)))

  try:
    if port > 0:
      server = await asyncio.start_server(handle_client, bind_ip, port)
      addr = server.sockets[0].getsockname()
      utils.log(f"Listing on {addr}")
    if tls_port > 0:
      ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
      ssl_ctx.load_cert_chain(config["DEFAULT"]["TLSCert"], config["DEFAULT"]["TLSCertKey"])
      tls_server = await asyncio.start_server(handle_client, bind_ip, tls_port, ssl=ssl_ctx)
      addr = tls_server.sockets[0].getsockname()
      utils.log(f"Listing on TLS {addr}")
  except Exception as e:
    utils.log(f"Error: {e}")
    return

  utils.log(f"Starting KIDL binary socket server v{VERSION}")

  async with server:
    await server.serve_forever()

def print_instructions():
  print("main.py -c <config.ini>")
  sys.exit(2)

if __name__ == "__main__":
  try:
    opts, args = getopt.getopt(sys.argv[1:], "c:", [ "conf=", ])
  except getopt.GetoptError:
    print_instructions()

  conf_file = ""

  for opt, arg in opts:
    if opt in ("-c", "--config"):
      conf_file = arg

  if not conf_file:
    print_instructions()

  config = utils.parse_config(conf_file)

  if not config:
    utils.log("Please check your config file and try again")
    exit(1)
  else:
    try:
      asyncio.run(start_server(config["DEFAULT"]["BindIP"], int(config["DEFAULT"]["Port"]), int(config["DEFAULT"]["TLSPort"])))
    except asyncio.exceptions.CancelledError:
      utils.log("Stopping server")
    except KeyboardInterrupt:
      utils.log("Stopping server")
    except Exception as e:
      utils.log(f"Fatal error: {e}")