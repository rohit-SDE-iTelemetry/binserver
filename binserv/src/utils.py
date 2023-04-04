import sys, os
import datetime
import pathlib
if os.name != "nt":
  import syslog
import logging
from logging.handlers import TimedRotatingFileHandler
import configparser

LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
ALTLOG_PRIORITY = "debug"

enable_syslog = False
enable_altlog = False

logger = logging.getLogger("binsrv")
logger.setLevel(logging.DEBUG)

def log(msg, priority="info"):
  if enable_syslog:
    if priority == "debug":
      syslog.syslog(syslog.LOG_DEBUG, str(msg))
    else:
      syslog.syslog(syslog.LOG_NOTICE, str(msg))
  if enable_altlog:
    if priority == "debug":
      logger.debug(str(msg))
    else:
      logger.info(str(msg))
  if sys.stdin.isatty():
    now = datetime.datetime.now().strftime(LOG_TIME_FORMAT)
    print(f"[{now}] {msg}")

def parse_config(conf_file):
  global enable_syslog
  global enable_altlog

  log(f"Reading '{conf_file}'")
  new_config = configparser.ConfigParser()
  try:
    new_config.read(conf_file)
  except Exception as e:
    log(f"Error: {e}")
    return False

  err = False

  required_confs = ( "BindIP", "Port", "TLSPort", "TLSCert", "TLSCertKey",
                     "Syslog", "Altlog", "AltlogRotatePeriod", "AltlogRotateKeep",
                     "IMEI",
                     "DataDirectory", "DataFormat", "DataNewFile", "DataIgnoreOld", "DataWriteInfoRecords",
                     "FirmwareDirectory", "FirmwareVersion",
                     "ConfDirectory" )
  for rc in required_confs:
    if not rc in new_config["DEFAULT"]:
      log(f"+ Missing {rc}", priority="debug")
      err = True

  if not err:
    int_confs = ( "Port", "TLSPort" )
    for intc in int_confs:
      try:
        intval = int(new_config["DEFAULT"][intc])
      except:
        log(f"+ Invalid {intc}: {new_config['DEFAULT'][intc]}", priority="debug")
        err = True

    yesno_confs = ( "Syslog", "Altlog", "DataNewFile", "DataIgnoreOld", "DataWriteInfoRecords" )
    for ync in yesno_confs:
      val = new_config["DEFAULT"][ync].lower()
      if val != "yes" and val != "no":
        log(f"+ Invalid {ync}: {val}", priority="debug")
        err = True
      for k_id in new_config.sections():
        val = new_config[k_id][ync].lower()
        if val != "yes" and val != "no":
          log(f"+ Invalid {ync} for {k_id}: {val}", priority="debug")
          err = True

    dir_confs = ( "AltlogDirectory", "DataDirectory", "FirmwareDirectory", "ConfDirectory" )
    for dc in dir_confs:
      if not os.access(new_config["DEFAULT"][dc], os.R_OK | os.W_OK):
        log(f"+ Unwritable {dc}: {new_config['DEFAULT'][dc]}", priority="debug")
        err = True
      for k_id in new_config.sections():
        if not os.access(new_config[k_id][dc], os.R_OK | os.W_OK):
          log(f"+ Unwritable {dc}: {new_config[k_id][dc]}", priority="debug")
          err = True

    if new_config["DEFAULT"]["TLSPort"].isnumeric() and int(new_config["DEFAULT"]["TLSPort"]) > 0:
      file_confs = ( "TLSCert", "TLSCertKey" )
      for fc in file_confs:
        if not os.access(new_config["DEFAULT"][fc], os.R_OK):
          log(f"+ Unreadable {fc}: {new_config['DEFAULT'][fc]}", priority="debug")
          err = True

  if err:
    return False

  if new_config["DEFAULT"]["Altlog"].lower() == "yes":
    try:
      handler = TimedRotatingFileHandler(filename=new_config["DEFAULT"]["AltlogDirectory"] + os.path.sep + "server.log",
                                         when=new_config["DEFAULT"]["AltlogRotatePeriod"],
                                         interval=1,
                                         backupCount=int(new_config["DEFAULT"]["AltlogRotateKeep"]))
      handler.setFormatter(logging.Formatter(fmt="[%(asctime)s] %(message)s", datefmt=LOG_TIME_FORMAT))
      logger.handlers.clear()
      logger.addHandler(handler)
    except Exception as e:
      log(f"Error: {e}")
      return False
    enable_altlog = True
  else:
    enable_altlog = False

  if os.name != "nt" and new_config["DEFAULT"]["Syslog"].lower() == "yes":
    enable_syslog = True
  else:
    enable_syslog = False

  return new_config

# For security, compare paths after resolving canonical path.
def secure_file_path(directory, filename):
  dir_path = os.path.realpath(directory)
  file_path = os.path.realpath(os.path.join(dir_path + os.path.sep + filename))

  if not os.path.isdir(dir_path):
    log("- Directory does not exist: " + dir_path)
    return False

  if file_path.find(dir_path + os.path.sep) != 0:
    log("- Blocking file access: " + file_path)
    return False

  return file_path
