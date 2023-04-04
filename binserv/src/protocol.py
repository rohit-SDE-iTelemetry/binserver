TIMEOUT                               = 10
MAX_ATTEMPTS                          = 3

MIN_FIRMWARE_FRAME_LENGTH             = 12
MAX_FIRMWARE_FRAME_LENGTH             = 1500

START_BYTE                            = b'\x02'
END_BYTE                              = b'\x03'

FRAME_TYPE_ID                         = b'\x00'
FRAME_TYPE_ACK                        = b'\x01'
FRAME_TYPE_NACK                       = b'\x02'
FRAME_TYPE_MEASDATA                   = b'\x03'
FRAME_TYPE_TIME_REQ                   = b'\x04'
FRAME_TYPE_TIME_CONFIRM               = b'\x05'
FRAME_TYPE_FIRMW_CHECK                = b'\x06'
FRAME_TYPE_FIRMW_AVAIL                = b'\x07'
FRAME_TYPE_FIRMW_DATA                 = b'\x08'
FRAME_TYPE_CONF_CHECK                 = b'\x09'
FRAME_TYPE_CONF_DATA                  = b'\x0A'
FRAME_TYPE_INFO_DATA                  = b'\x0B'
FRAME_TYPE_SETTINGS_DATA              = b'\x0C'
FRAME_TYPE_CLOSE                      = b'\x0D'
FRAME_TYPE_FIRMW_CHECK2               = b'\x0E'
FRAME_TYPE_FIRMW_AVAIL2               = b'\x0F'
FRAME_TYPE_FIRMW_RESUME               = b'\x10'
#FRAME_TYPE_MAX_TYPE_ID               = b'\x11' # Used by KIDL internally

ACK_NONE                              = b'\x00'

NACK_NONE                             = b'\x00'
NACK_BADCRC                           = b'\x01'
NACK_ID_UNKNOWN                       = b'\x02'
NACK_NO_FIRMWARE                      = b'\x03'
NACK_NO_CONF                          = b'\x04'