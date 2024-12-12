#!/usr/bin/env python3

# UART Sniffer for the tuya serial port protocol (between main MCU and tuya zigbee module)
# version 1.0 (c) dUkk 2024
# UART RX-pin of COM port shiffer should be connected according to required eyedropping flow direction (on RX of mcu or on TX of mcu)
# you can run two instances of sniffer if you have two USB-UART bridges to eyedrop on 2way communication
# !!!Use at your own risk and do proper galvanic isolation between DUT and USB-UART bridge!!!

import serial
import argparse
import structlog
import sys
import logging
from struct import pack,unpack
from enum import Enum
from binascii import hexlify

# https://developer.tuya.com/en/docs/iot/tuya-zigbee-module-uart-communication-protocol?id=K9ear5khsqoty
# https://developer.tuya.com/en/docs/iot/tuya-zigbee-universal-docking-access-standard?id=K9ik6zvofpzql
class FrameType(Enum):
    FACTORY_RESET=0  # module notifies the MCU of factory reset initiated by the mobile app
    PRODUCT_INFO=1  # module requests the product information from the MCU.
    CUR_NET_STATUS=2  # module reports the current network status to the MCU.
    CONFIGURATION_DATA=3  # MCU sends a configuration command to the Zigbee module
    ZB_TO_MCU_COMMAND=4  # module sends a command to the MCU
    MCU_TOZB_RESPONSE=5  # MCU responds to a command
    DATA_QUERY=6  # MCU proactively reports status to the module.
    RESERVED_CMD=7  # Reserved command
    TEST_RF_PERF=8  # MCU initiates a test of the radio frequency (RF) performance.
    KEY_CONFIG=9  # module requests the key configuration from the MCU.
    SCENE_START=0x0a  # MCU instructs the module to run a specific scene
    FIRMWARE_VERSION=0x0b  # module requests the MCU firmware version.
    OTA_FW_NOTIFY=0x0c  # module notifies the MCU of an OTA firmware update
    REQUEST_UPDATE=0x0d  # MCU requests to download the updates
    UPDATE_RESULT=0x0e  # MCU returns the update result.
    QUERY_ZB_NET_STATUS=0x20  # Query Zigbee network status
    REQUEST_SYNC_TS=0x24  # MCU requests to sync clock time with the server time
    REQUEST_GW_CONN_STATUS=0x25  # MCU requests gateway connection status
    SET_NET_POLICY=0x26  # MCU instructs the module to set the Zigbee network policy parameters
    DP_DATA_BROADCAST=0x27  # module sends the MCU the DP data over broadcast
    REPORT_DP_DATA=0x28  # module instructs the MCU to report DP data
    ENTER_TEST_MODE=0x29  # When receiving beacon signals after power-on, the module instructs the MCU to enter the test mode
    GET_LOCAL_TIME=0x1c  # Get local time
    PRIVATE_COMMAND=0x43  # MCU sends multicast messages with private commands

class DPType(Enum):
    RAW = 0
    BOOLEAN = 1  # boolean data 0/1
    INTEGER = 2  # integer data
    STRING = 3  # string data
    ENUM = 4  # enum data 0/1/2/3/4/5 
    FAULT = 5  # fault data

encountered_types = []
encountered_datapoints = []

LOG_LEVEL_NAMES = [logging.getLevelName(v) for v in
                   sorted(getattr(logging, '_levelToName', None) or logging._levelNames) if getattr(v, "real", 0)]

log = structlog.get_logger()

def pkt_checksum(pkt):
    sum = 0
    log.debug('calculating checksum', pkt=pkt)
    for c in pkt:
        log.debug('c', c=c)
        sum = (sum + c) & 0xff
    return sum

def print_statistics():
    print('unique encountered command frame types')
    for item in encountered_types:
        print('cmd: {0}'.format(item))
    print('unique encountered datatypes')
    for item in encountered_datapoints:
        print('DP id: {0}  hex: {0:02X}'.format(item))
    

if __name__ == "__main__":
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr)
    )

    parser = argparse.ArgumentParser(description='TuyaMCU Serial Protocol Sniffer')
    parser.add_argument('--loglevel', choices=LOG_LEVEL_NAMES, default='INFO', help='Change log level')
    parser.add_argument('serial_port', help='Serial port. (ex. COM1)')
    parser.add_argument('baud_rate', help='baud rate 9600 or 115200')

    args = parser.parse_args()
    config = args

    # Restrict log message to be above selected level
    structlog.configure( wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, args.loglevel)) )

    log.debug('config', config=config)

    log.info('opening serial port', url=config.serial_port)
    do_work = True
    with serial.serial_for_url(config.serial_port, int(config.baud_rate),  bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=1) as ser:
        buffer = bytes()
        while do_work:
                try:
                    buffer += ser.read(ser.inWaiting())
                except KeyboardInterrupt:
                    log.info('stopped')
                    print_statistics()
                    break;
                
                while len(buffer) > 8:
                    
                    (hdr, proto_ver, seq_num, frame_type, payload_len) = unpack('>HBHBH', buffer[:8])
                    if hdr != 0x55AA:
                        log.error('invalid start frame header', header=hexlify(buffer[:8]))
                        buffer = buffer[1:] # make single byte step (probably lost sync)
                        break
       
                    # try read frame data
                    try:
                        buffer += ser.read(payload_len + 1)
                    except KeyboardInterrupt:
                        log.info('stopped')
                        print_statistics()
                        do_work = False
                        break;
                        
                    if len(buffer)-9 < payload_len:
                        log.debug('not enough data in port for full frame payload!')
                        break
                    
                    (checksum, ) = unpack('B', buffer[8+payload_len:9+payload_len])
                    if pkt_checksum(buffer[:8+payload_len]) != checksum:
                        log.warn('invalid frame checksum', checksum=hex(checksum), should_be=hex(pkt_checksum(buffer[:8+payload_len])))
                    
                    frame_type = FrameType(frame_type)                    
                    log.info('tuyamcu frame', version=proto_ver, seq=seq_num, type=frame_type, size=payload_len)
                    
                    if frame_type not in encountered_types:
                        encountered_types.append(frame_type)
                    
                    if frame_type == FrameType.PRODUCT_INFO:
                        log.info('product info', productjson=buffer[8:8+payload_len].decode('ascii'))
                    elif frame_type == FrameType.DATA_QUERY:
                        if payload_len > 4:
                            (tuya_DP_id, tuya_datatype, tuya_data_len) = unpack('>BBH', buffer[8:8+4])
                            tuya_datatype = DPType(tuya_datatype)
                            
                            if tuya_DP_id not in encountered_datapoints:
                                encountered_datapoints.append(tuya_DP_id)
                            
                            if tuya_datatype == DPType.BOOLEAN:
                               log.info('tuya embedded data', DPid=tuya_DP_id, DPidHEX=hexlify(buffer[8:9]), type=tuya_datatype, value = unpack('?', buffer[8+4:8+4+tuya_data_len])) 
                            elif tuya_datatype == DPType.INTEGER:
                               log.info('tuya embedded data', DPid=tuya_DP_id, DPidHEX=hexlify(buffer[8:9]), type=tuya_datatype, value = unpack('>I', buffer[8+4:8+4+tuya_data_len]))                             
                            elif tuya_datatype == DPType.STRING:
                                log.info('tuya embedded data', DPid=tuya_DP_id, DPidHEX=hexlify(buffer[8:9]), type=tuya_datatype, string = buffer[8+4:8+4+tuya_data_len].decode('ascii'))                             
                            else:
                                log.info('tuya embedded data', DPid=tuya_DP_id, DPidHEX=hexlify(buffer[8:9]), type=tuya_datatype, len=tuya_data_len, payload=hexlify(buffer[8+4:8+4+tuya_data_len])) 
                    
                    # remove processed bytes from circular buffer
                    buffer = buffer[9+payload_len:]
