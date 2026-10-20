# (c) Wholesome Software 15 Oct 2026
# This is AI-assisted conversion of official Tuya Serial Zigbee Communication Protocol documentation
# Serial Communication Protocol_MCU Standard Protocol_MCU Standard Protocol.pdf dated 2025 year
# to the simplify building sniffer that helps a lot while debugging Tuya with second MCU devices
# it was intended to use with devices where two MCU are present back2back - Tuya based and some third party ones communicated over UART.
# it was eyedropping on packets between two MCU and decode tuya v2 protocol (zigbee devices use it)
#
# to use it properly:
# 1.
# solder RX and TX lines wires from tuya RF module to the RX double UART to USB bridge (for example FTDI 2232H)
# Tuya TX --->  RX UART0 of FTDI2232H
# Tuya RX --->  RX UART1 of FTDI2232H
# or you can use any other TWO usb-to-uart bridges.
# 2.
# modify PORT_1 and PORT_2 below accordingly 

import threading
import time
import json
from datetime import datetime
import serial

PORT_1 = "COM8"   #it was TX line on tuya module
PORT_2 = "COM9"   #it was RX line on tuya module
BAUDRATE = 115200
HEADER = b"\x55\xAA"

PORT_ROLES = {
    PORT_1: "MCU",
    PORT_2: "ZIGBEE_MODULE",
}

COMMANDS_DICT = {
    0x00: {"sender": "Z", "desc": "Unbind and clear data"},
    0x01: {"sender": "Z", "desc": "Query product information"},
    0x02: {"sender": "Z", "desc": "Sync module's network status"},
    0x03: {"sender": "M", "desc": "Reset or pair module"},
    0x07: {"sender": "M", "desc": "Query module information"},
    0x20: {"sender": "M", "desc": "Query module's network status"},
    0x25: {"sender": "M", "desc": "Check gateway's network status"},
    0x2B: {"sender": "M", "desc": "Set wake-up waiting time"},
    0x04: {"sender": "Z", "desc": "Receive DP data"},
    0x05: {"sender": "M", "desc": "Respond to DP data"},
    0x06: {"sender": "M", "desc": "Report DP data (trigger linkage)"},
    0x26: {"sender": "M", "desc": "Configure Zigbee network parameters"},
    0x27: {"sender": "M", "desc": "Send advertising packets"},
    0x28: {"sender": "Z", "desc": "Query DP data"},
    0x2A: {"sender": "Z", "desc": "Receive DP data (group control)"},
    0x2C: {"sender": "M", "desc": "Report DP data (not trigger linkage)"},
    0x43: {"sender": "M", "desc": "Send private commands via multicast"},
    0x08: {"sender": "M", "desc": "Test module's RF functionality"},
    0x0A: {"sender": "M", "desc": "Trigger scenes"},
    0x0B: {"sender": "Z", "desc": "Query MCU firmware version"},
    0x0C: {"sender": "Z", "desc": "Initiate OTA update"},
    0x21: {"sender": "Z", "desc": "Notify the MCU of a dongle test"},
    0x22: {"sender": "M", "desc": "Report dongle test data"},
    0x29: {"sender": "Z", "desc": "Notify the MCU of a beacon-triggered test"},
    0x41: {"sender": "Z", "desc": "Configure scenes"},
    0x42: {"sender": "M", "desc": "Send standard commands via multicast"},
    0x0D: {"sender": "M", "desc": "Request firmware updates"},
    0x0E: {"sender": "M", "desc": "Report update result"},
    0x24: {"sender": "M", "desc": "Sync time"},
    0x36: {"sender": "M", "desc": "Configure GPIO pins"},
    0x37: {"sender": "M", "desc": "Read GPIO level"},
    0x38: {"sender": "M", "desc": "Control GPIO output"},
    0x39: {"sender": "M", "desc": "Sync GPIO interrupt"},
    0x3A: {"sender": "M", "desc": "Request weather information"},
    0x3B: {"sender": "Z", "desc": "Sync weather information"},
    0x4A: {"sender": "M", "desc": "Initiate distributed linkage control"},
    0x4B: {"sender": "M", "desc": "Configure distributed linkage broadcast DPs"},
}


def parse_dp_data(data_bytes):
    dp_outputs = []
    idx = 0
    
    dp_types = {
        0x00: "Raw",
        0x01: "Boolean",
        0x02: "Value (Int)",
        0x03: "String",
        0x04: "Enum",
        0x05: "Bitmap"
    }

    while idx < len(data_bytes):
        if idx + 4 > len(data_bytes):
            dp_outputs.append(f"[Eror DP: remaining bytes are too short for a header: {data_bytes[idx:].hex().upper()}]")
            break

        dp_id = data_bytes[idx]
        dp_type_raw = data_bytes[idx + 1]
        
        dp_len = int.from_bytes(data_bytes[idx + 2:idx + 4], byteorder='big')
        
        value_start = idx + 4
        value_end = value_start + dp_len

        if value_end > len(data_bytes):
            dp_outputs.append(f"[Error DP ID {dp_id}: expected {dp_len} byte of the value, but in the buffer only {len(data_bytes) - value_start}]")
            break

        value_bytes = data_bytes[value_start:value_end]
        dp_type_str = dp_types.get(dp_type_raw, f"Unknown (0x{dp_type_raw:02X})")
        
        decoded_val = ""
        
        if dp_type_raw == 0x00:  # Raw
            decoded_val = " ".join(f"{b:02X}" for b in value_bytes)
            
        elif dp_type_raw == 0x01:  # Boolean
            if len(value_bytes) == 1:
                decoded_val = "True" if value_bytes[0] == 0x01 else "False"
            else:
                decoded_val = f"Invalid Len ({len(value_bytes)})"
                
        elif dp_type_raw == 0x02:  # Int value
            if len(value_bytes) == 4:
                decoded_val = str(int.from_bytes(value_bytes, byteorder='big'))
            else:
                decoded_val = str(int.from_bytes(value_bytes, byteorder='big')) + " (size != 4B)"
                
        elif dp_type_raw == 0x03:  # String
            try:
                decoded_val = value_bytes.decode('utf-8', errors='replace')
            except Exception:
                decoded_val = "String decoding error"
                
        elif dp_type_raw == 0x04:  # Enum (1 byte, 0 to 255)
            if len(value_bytes) == 1:
                decoded_val = f"{value_bytes[0]} (0x{value_bytes[0]:02X})"
            else:
                decoded_val = str(int.from_bytes(value_bytes, byteorder='big'))
                
        elif dp_type_raw == 0x05:  # Bitmap (1, 2 or 4 bytes)
            decoded_val = "0x" + "".join(f"{b:02X}" for b in value_bytes)
            
        else:
            decoded_val = " ".join(f"{b:02X}" for b in value_bytes)

        dp_outputs.append(f"DP_ID: {dp_id} (0x{dp_id:02X}) [{dp_type_str}] = {decoded_val}")
        
        idx = value_end

    return dp_outputs


def parse_gpio_36_data(data_bytes, port_role):
    if not data_bytes:
        return ["[Payload is empty]"]

    num_gpios = data_bytes[0]
    idx = 1
    outputs = [f"Number of GPIOs in packet: {num_gpios}"]

    gpio_modes = {
        0: "INPUT_HIGH_IMPEDANCE (Input, High-Z)",
        1: "INPUT_PULL (Input with pull up",
        2: "OUTPUT_PP (Output Push-Pull)",
        3: "OUTPUT_OD (Output Open-Drain)",
        4: "OUTPUT_OD_PULL_UP (Output OD with pull up)",
        5: "OUTPUT_OD_PULL_DOWN (Output OD with pull down)"
    }

    gpio_levels = {
        0: "LOW (low level / interrupt falling)",
        1: "HIGH (high level / interrupt raising)",
        2: "ALL (interrupt on fall/down)"
    }

    if port_role == "MCU":
        pin_count = 1
        while idx < len(data_bytes):
            if idx + 4 > len(data_bytes):
                outputs.append(f"  [Error]: remaining number of bytes is too small")
                break
            
            port_num = data_bytes[idx]
            pin_num  = data_bytes[idx+1]
            mode_val = data_bytes[idx+2]
            lvl_val  = data_bytes[idx+3]

            mode_str = gpio_modes.get(mode_val, f"Unknown (0x{mode_val:02X})")
            lvl_str = gpio_levels.get(lvl_val, f"Unknown (0x{lvl_val:02X})")

            outputs.append(f"  PIN {pin_count} -> Port: {port_num}, Pin: {pin_num} | Mode: {mode_str} | Trigger/Level: {lvl_str}")
            idx += 4
            pin_count += 1

    elif port_role == "ZIGBEE_MODULE":
        pin_count = 1
        while idx < len(data_bytes):
            if idx + 3 > len(data_bytes):
                outputs.append(f"  [Error]: remaining bytes are too few for the configuration result")
                break

            port_num = data_bytes[idx]
            pin_num  = data_bytes[idx+1]
            status_val = data_bytes[idx+2]

            status_str = "Success" if status_val == 0x00 else f"Failed (Error 0x{status_val:02X})"

            outputs.append(f"  PIN {pin_count} -> Port: {port_num}, Pin: {pin_num} | Status: {status_str}")
            idx += 3
            pin_count += 1
            
    else:
        outputs.append(f"Raw GPIO bytes (Unknown port role): {data_bytes[1:].hex().upper()}")

    return outputs


def parse_gpio_37_data(data_bytes, port_role):
    if not data_bytes:
        return ["[Payload is empty]"]

    num_gpios = data_bytes[0]
    idx = 1
    outputs = [f"Number of GPIOs in packet: {num_gpios}"]

    gpio_levels = {
        0: "LOW (low level)",
        1: "HIGH (High level)"
    }

    if port_role == "MCU":
        pin_count = 1
        while idx < len(data_bytes):
            if idx + 2 > len(data_bytes):
                outputs.append(f"  [Error]: remaining number of bytes is too small")
                break
            
            port_num = data_bytes[idx]
            pin_num  = data_bytes[idx+1]

            outputs.append(f"  PIN {pin_count} -> Read request: Port: {port_num}, Pin: {pin_num}")
            idx += 2
            pin_count += 1

    elif port_role == "ZIGBEE_MODULE":
        pin_count = 1
        while idx < len(data_bytes):
            if idx + 3 > len(data_bytes):
                outputs.append(f"  [Error]: remaining number of bytes is too small")
                break

            port_num = data_bytes[idx]
            pin_num  = data_bytes[idx+1]
            lvl_val  = data_bytes[idx+2]

            lvl_str = gpio_levels.get(lvl_val, f"Unknown/Error (0x{lvl_val:02X})")

            outputs.append(f"  PIN {pin_count} -> Port: {port_num}, Pin: {pin_num} | Current level: {lvl_str}")
            idx += 3
            pin_count += 1
            
    else:
        outputs.append(f"Raw GPIO bytes (Unknown port role): {data_bytes[1:].hex().upper()}")

    return outputs


def parse_gpio_38_data(data_bytes, port_role):
    if not data_bytes:
        return ["[Payload is empty]"]

    num_gpios = data_bytes[0]
    idx = 1
    outputs = [f"Number of GPIOs in packet: {num_gpios}"]

    gpio_levels = {
        0: "LOW (set low level)",
        1: "HIGH (set high level)"
    }
    gpio_statuses = {
        0x00: "Success",
        0x01: "Failure"
    }

    if port_role == "MCU":
        pin_count = 1
        while idx < len(data_bytes):
            if idx + 3 > len(data_bytes):
                outputs.append("  [Error]: remaining number of bytes is too small")
                break
            
            port_num = data_bytes[idx]
            pin_num  = data_bytes[idx+1]
            lvl_val  = data_bytes[idx+2]

            lvl_str = gpio_levels.get(lvl_val, f"Unknown (0x{lvl_val:02X})")

            outputs.append(f"  PIN {pin_count} -> Port: {port_num}, Pin: {pin_num} | Action: {lvl_str}")
            idx += 3
            pin_count += 1

    elif port_role == "ZIGBEE_MODULE":
        pin_count = 1
        while idx < len(data_bytes):
            if idx + 3 > len(data_bytes):
                outputs.append("  [Error]: remaining number of bytes is too small")
                break

            port_num = data_bytes[idx]
            pin_num  = data_bytes[idx+1]
            status_val = data_bytes[idx+2]

            status_str = gpio_statuses.get(status_val, f"Unknown status (0x{status_val:02X})")

            outputs.append(f"  PIN {pin_count} -> Port: {port_num}, Pin: {pin_num} | Result: {status_str}")
            idx += 3
            pin_count += 1
            
    else:
        outputs.append(f"Raw GPIO bytes (Unknown port role): {data_bytes[1:].hex().upper()}")

    return outputs


def parse_gpio_39_data(data_bytes, port_role):
    outputs = []
    
    gpio_levels = {
        0: "LOW (low level)",
        1: "HIGH (high level)"
    }

    if port_role == "ZIGBEE_MODULE":
        if len(data_bytes) == 3:
            port_num = data_bytes[0]
            pin_num  = data_bytes[1]
            lvl_val  = data_bytes[2]
            
            lvl_str = gpio_levels.get(lvl_val, f"Unknown (0x{lvl_val:02X})")
            outputs.append(f"Encountered interrupt on pin -> Port: {port_num}, Pin: {pin_num} | new level: {lvl_str}")
        else:
            outputs.append(f"[Error]: expected 3 bytes interrupt, but got: {len(data_bytes)}B")

    elif port_role == "MCU":
        if len(data_bytes) == 0:
            outputs.append("acceptance (ACK): MCU success got interrrupt")
        else:
            outputs.append(f"[Warning]: MCU sent unexpected data ({len(data_bytes)}B)")
            
    else:
        outputs.append(f"Raw GPIO bytes (Unknown port role): {data_bytes.hex().upper()}")

    return outputs


def parse_cmd_07_data(data_bytes, port_role):
    if not data_bytes:
        return ["[Payload is empty]"]

    outputs = []
    info_types = {
        0x01: "Firmware version number",
        0x02: "Authorization information",
        0x03: "MAC address"
    }

    if port_role == "MCU":
        requested_ids = [f"0x{b:02X} ({info_types.get(b, 'Unknown')})" for b in data_bytes]
        outputs.append(f"Request for information for an ID: {', '.join(requested_ids)}")

    elif port_role == "ZIGBEE_MODULE":
        idx = 0
        block_count = 1
        while idx < len(data_bytes):
            info_type = data_bytes[idx]
            type_str = info_types.get(info_type, f"Unknown type (0x{info_type:02X})")
            
            if info_type in (0x01, 0x02):
                if idx + 2 > len(data_bytes):
                    outputs.append(f"  [Block {block_count}]: Error — remaining number of bytes is too small for the type 0x{info_type:02X}")
                    break
                payload_byte = data_bytes[idx+1]
                outputs.append(f"  Block {block_count} -> Type: {type_str} | Data: 0x{payload_byte:02X} ({payload_byte})")
                idx += 2
            elif info_type == 0x03:
                if idx + 9 > len(data_bytes):
                    outputs.append(f"  [Block {block_count}]: Error — the remaining number of bytes is too small for a MAC address")
                    break
                mac_bytes = data_bytes[idx+1:idx+9]
                mac_str = ":".join(f"{b:02X}" for b in mac_bytes)
                outputs.append(f"  Block {block_count} -> Type: {type_str} | Data (Hex): {mac_str}")
                idx += 9
            else:
                raw_rest = " ".join(f"{b:02X}" for b in data_bytes[idx:])
                outputs.append(f"  [Block {block_count}]: Unknown data structure type 0x{info_type:02X}. Remaining: {raw_rest}")
                break
                
            block_count += 1
    else:
        outputs.append(f"Raw bytes of information about the module: {data_bytes.hex().upper()}")

    return outputs


def parse_cmd_2B_data(data_bytes, port_role):
    if not data_bytes and port_role != "MCU":
        return ["[Payload is empty]"]

    outputs = []

    if port_role == "MCU":
        timeout_ms = int.from_bytes(data_bytes, byteorder='big')
        outputs.append(f"Setting the wake-up timeout: {timeout_ms} ms. (Acceptable: 3-300 ms, default: 5 ms)")

    elif port_role == "ZIGBEE_MODULE":
        if len(data_bytes) == 1:
            status_val = data_bytes[0]
            status_desc = "Success (Успешно)" if status_val == 0x01 else f"Failure (Error 0x{status_val:02X})"
            outputs.append(f"Результат настройки: {status_desc}")
        else:
            outputs.append(f"[Error]: Expected single byte answer, but got: {len(data_bytes)}B")
            
    else:
        outputs.append(f"Raw bytes for cmd 0x2B: {data_bytes.hex().upper()}")

    return outputs


def parse_cmd_3B_data(data_bytes):
    if len(data_bytes) < 3:
        return ["[Payload is too small]"]

    outputs = []
    ver = data_bytes[0]
    loc_type = data_bytes[1]
    msg_type = data_bytes[2]

    loc_str = "Device location" if loc_type == 0x00 else "Home location (App)"
    outputs.append(f"Weather protocol version: 0x{ver:02X} | Location: {loc_str}")
-
    if msg_type == 0x12:
        if len(data_bytes) < 6:
            return outputs + ["[Error]: Incomplete weather data header"]

        forecast_days = data_bytes[3]
        current_flag = data_bytes[4]
        current_enabled = (data_bytes[5] == 0x01)

        outputs.append(f"Weather parameters -> Forecast days: {forecast_days}, Current weather: {'Included' if current_enabled else 'Excluded'}")

        # Fmt: (Name, size in bytes, sign flag True=signed/False=unsigned, multiplier for output)
        weather_meta = {
            1:  ("Temperature", 2, True, 1.0),
            2:  ("Humidity", 2, False, 1.0),
            3:  ("ConditionNum", 1, False, 1.0),
            4:  ("RealFeel", 2, True, 1.0),
            5:  ("uvi (UV-index)", 1, False, 1.0),
            6:  ("windSpeed", 1, False, 0.1),
            7:  ("windDir", 1, False, 1.0),
            8:  ("windLevel", 1, False, 1.0),
            9:  ("aqi", 2, False, 1.0),
            10: ("Pm10 (PM10)", 2, False, 1.0),
            11: ("Pm25 (PM2.5)", 2, False, 1.0),
            12: ("O3", 2, False, 1.0),
            13: ("No2", 2, False, 1.0),
            14: ("Co", 2, False, 1.0),
            15: ("So2", 2, False, 1.0),
            16: ("T-high", 2, True, 1.0),
            17: ("T-low", 2, True, 1.0),
            18: ("Data (Number of days forecast)", 1, False, 1.0),
            19: ("Currdate (flag)", 1, False, 1.0),
        }

        idx = 6
        while idx < len(data_bytes):
            w_id = data_bytes[idx]
            idx += 1

            if w_id not in weather_meta:
                outputs.append(f"  └── [Unknown Weather ID: {w_id}]. parsing stopped.")
                break

            name, byte_len, is_signed, scale = weather_meta[w_id]
            param_details = []

            def read_val(b_array, start_pos):
                val = int.from_bytes(b_array[start_pos:start_pos+byte_len], byteorder='big', signed=is_signed)
                return f"{val * scale:.1f}" if scale != 1.0 else str(val)

            if current_enabled:
                if idx + byte_len > len(data_bytes):
                    outputs.append(f"  └── [Error]: Insufficient bytes for the current value ID {w_id}")
                    break
                param_details.append(f"Now: {read_val(data_bytes, idx)}")
                idx += byte_len

            if forecast_days > 0:
                forecast_vals = []
                for d in range(forecast_days):
                    if idx + byte_len > len(data_bytes):
                        outputs.append(f"  └── [Error]: Incomplete forecast data for ID {w_id} for day {d+1}")
                        break
                    forecast_vals.append(read_val(data_bytes, idx))
                    idx += byte_len
                if forecast_vals:
                    param_details.append(f"Forecast: [" + ", ".join(forecast_vals) + "]")

            outputs.append(f"  ├── ID {w_id:02d} ({name}) -> " + " | ".join(param_details))

    elif msg_type == 0x63:
        idx = 2
        if idx + 6 <= len(data_bytes) and data_bytes[idx:idx+6] == b'c.area':
            idx += 6
            next_flag = data_bytes.find(b'c.city', idx)
            end_name_idx = next_flag if next_flag != -1 else len(data_bytes)
            
            district_name = data_bytes[idx:end_name_idx].decode('utf-8', errors='replace').strip()
            outputs.append(f"Geo-tagging -> District/Region: {district_name}")
            idx = end_name_idx

        if idx + 6 <= len(data_bytes) and data_bytes[idx:idx+6] == b'c.city':
            idx += 6
            city_name = data_bytes[idx:].decode('utf-8', errors='replace').strip()
            outputs.append(f"Geo-tagging -> City: {city_name}")

    else:
        outputs.append(f"Raw bytes for cmd 0x3B: {data_bytes.hex().upper()}")

    return outputs


def print_packet(port_name, packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    if len(packet) < 9:
        hex_data = " ".join(f"{b:02X}" for b in packet)
        print(f"[{timestamp}] [{port_name}] -> [INCOMPLETE FRAME] {hex_data}")
        return

    header_bytes = packet[0:2]
    version_byte = packet[2]
    seq_bytes    = packet[3:5]
    cmd_byte     = packet[5]
    len_bytes    = packet[6:8]
    data_bytes   = packet[8:-1]
    checksum_byte = packet[-1]

    seq_num = int.from_bytes(seq_bytes, byteorder='big')
    data_len_expected = int.from_bytes(len_bytes, byteorder='big')

    if cmd_byte in COMMANDS_DICT:
        cmd_info = COMMANDS_DICT[cmd_byte]
        spec_sender = cmd_info["sender"]  
        cmd_desc = f"'{cmd_info['desc']}'"
    else:
        spec_sender = None
        cmd_desc = "Unknown command"

    current_port_role = PORT_ROLES.get(port_name, "UNKNOWN")
    
    if spec_sender:
        spec_sender_role = "MCU" if spec_sender == "M" else "ZIGBEE_MODULE"

        if current_port_role == spec_sender_role:
            destination = "ZIGBEE_MODULE" if current_port_role == "MCU" else "MCU"
            direction_str = f"{current_port_role} -> {destination} (Question)"
        else:
            direction_str = f"{spec_sender_role} -> {current_port_role} (Answer)"
    else:
        direction_str = f"Port: {current_port_role}"

    calculated_checksum = sum(packet[:-1]) % 256
    checksum_status = "OK" if calculated_checksum == checksum_byte else f"Error (expected {calculated_checksum:02X})"

    str_header = " ".join(f"{b:02X}" for b in header_bytes)
    str_version = f"{version_byte:02X}"
    str_seq = " ".join(f"{b:02X}" for b in seq_bytes)
    str_cmd = f"{cmd_byte:02X}"
    str_len = " ".join(f"{b:02X}" for b in len_bytes)
    str_data = " ".join(f"{b:02X}" for b in data_bytes) if data_bytes else "[data is empty]"
    str_checksum = f"{checksum_byte:02X}"

    output_lines = [
        f"[{timestamp}] [{direction_str}]",
        f"  ├─ Structure: {str_header} | {str_version} | {str_seq} | {str_cmd} | {str_len} | {str_data} | {str_checksum}",
        f"  └─ Decoded: Version: {version_byte}, Sequence number: {seq_num}, CMD: 0x{str_cmd} -> {cmd_desc}, Payload size: {len(data_bytes)} of {data_len_expected} bytes, CRC: {checksum_status}"
    ]

    # (Product Information JSON) ---
    if cmd_byte == 0x01 and data_bytes:
        try:
            json_str = data_bytes.decode('utf-8', errors='replace').strip()
            prod_info = json.loads(json_str)
            
            output_lines.append("  └─ [Product information (JSON)]:")
            
            if 'p' in prod_info:
                output_lines.append(f"       ├── Product ID (p): {prod_info['p']}")
            if 'v' in prod_info:
                output_lines.append(f"       ├── MCU Firmware Ver (v): {prod_info['v']}")
            if 'g' in prod_info:
                g_val = "1 (Unicast/Multicast Separation ON)" if str(prod_info['g']) == "1" else f"{prod_info['g']} (OFF)"
                output_lines.append(f"       ├── Multicast Flag (g): {g_val}")
            if 's' in prod_info:
                s_val = "1 (Supports scenes ON)" if str(prod_info['s']) == "1" else f"{prod_info['s']} (OFF)"
                output_lines.append(f"       ├── Scene Support (s): {s_val}")
            if 'lp' in prod_info:
                lp_val = "1 (Low Power Mode ON)" if str(prod_info['lp']) == "1" else f"{prod_info['lp']} (OFF)"
                output_lines.append(f"       ├── Low Power Mode (lp): {lp_val}")

            output_lines[-1] = output_lines[-1].replace("├──", "└──")
            
        except json.JSONDecodeError:
            output_lines.append(f"  └─ [Error JSON]: cant parse string: {data_bytes.decode('utf-8', errors='replace')}")
        except Exception as e:
            output_lines.append(f"  └─ [Exception parsing 0x01]: {e}")

    # (Network Status) ---
    if cmd_byte == 0x02 and len(data_bytes) >= 1:
        status_byte = data_bytes[0]
        network_statuses = {
            0x00: "Not connected (Device powered on for the first time, fails to pair, or removed)",
            0x01: "Connected (Device has been added to a Zigbee network)",
            0x02: "Network error",
            0x03: "The device is being paired"
        }
        
        status_desc = network_statuses.get(status_byte, f"Unknown status (0x{status_byte:02X})")
        output_lines.append(f"  └─ [RF Module network status]: {status_desc}")
    
    # (Reset or pair module) ---
    if cmd_byte == 0x03:
        if len(data_bytes) == 0:
            output_lines.append("  └─ [Confirmation of completion (ACK)]: Data successfully received by the module")
        elif len(data_bytes) == 1:
            mode_byte = data_bytes[0]
            mode_statuses = {
                0x00: "Reset and restart",
                0x01: "Leave the current network and join a new one"
            }
            mode_desc = mode_statuses.get(mode_byte, f"Unknown mode (0x{mode_byte:02X})")
            output_lines.append(f"  └─ [change mode command]: {mode_desc}")

    # DP related parsing
    dp_commands = {0x04, 0x05, 0x06, 0x28, 0x2A, 0x2C}
    if cmd_byte in dp_commands and data_bytes:
        if cmd_byte in {0x05, 0x06} and len(data_bytes) == 1:
            ack_byte = data_bytes[0]
            ack_statuses = {
                0x00: "Error",
                0x01: "Success",
            }
            ack_desc = ack_statuses.get(ack_byte, f"Unknown ACK status (0x{ack_byte:02X})")
            output_lines.append(f"  └─ [Confirmation of completion (ACK)]: {ack_desc}")
        else:
            dp_results = parse_dp_data(data_bytes)
            if dp_results:
                output_lines.append("  └─ [Parsing DP Message]:")
                for dp_line in dp_results:
                    output_lines.append(f"       ├── {dp_line}")
                output_lines[-1] = output_lines[-1].replace("├──", "└──")

    # (Query module information) ---
    if cmd_byte == 0x07:
        info_results = parse_cmd_07_data(data_bytes, current_port_role)
        if info_results:
            output_lines.append("  └─ [Analysis of information about the module]:")
            for info_line in info_results:
                output_lines.append(f"       ├── {info_line}")
            output_lines[-1] = output_lines[-1].replace("├──", "└──")

    # (Query MCU firmware version) ---
    if cmd_byte == 0x0B and len(data_bytes) == 1:
        ver_byte = data_bytes[0]
        
        # fmt xx.yy.zzzz
        major = (ver_byte >> 6) & 0x03
        minor = (ver_byte >> 4) & 0x03
        patch = ver_byte & 0x0F
        
        output_lines.append(f"  └─ [Firmware version MCU]: binary 0x{ver_byte:02X} -> {major}.{minor}.{patch}")

    # (Sync time) ---
    if cmd_byte == 0x24 and len(data_bytes) == 8:
        unix_ts = int.from_bytes(data_bytes[0:4], byteorder='big')
        local_ts = int.from_bytes(data_bytes[4:8], byteorder='big')
        
        try:
            unix_time_str = datetime.fromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            unix_time_str = "invalid timestamp"
            
        try:
            local_time_str = datetime.fromtimestamp(local_ts).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            local_time_str = "invalid timestamp"

        output_lines.append(
            f"  └─ [Time and date synchonization]:\n"
            f"       ├── Unix Timestamp:  {unix_ts} -> {unix_time_str}\n"
            f"       └── Local Timestamp: {local_ts} -> {local_time_str}"
        )

    # (Configure Zigbee network parameters) ---
    if cmd_byte == 0x26 and len(data_bytes) == 14:
        heartbeat = int.from_bytes(data_bytes[0:2], byteorder='big')
        pairing_timeout = int.from_bytes(data_bytes[2:4], byteorder='big')
        rejoin_interval = int.from_bytes(data_bytes[4:6], byteorder='big')
        poll_interval = int.from_bytes(data_bytes[6:8], byteorder='big')
        fast_poll_time = int.from_bytes(data_bytes[8:10], byteorder='big')
        
        max_failed_polls = data_bytes[10]
        rejoin_by_mcu = data_bytes[11]
        max_rejoin_times = data_bytes[12]
        
        rejoin_mcu_str = "1 (Enable)" if rejoin_by_mcu == 1 else f"{rejoin_by_mcu} (Disable)"

        output_lines.append(
            f"  └─ [Zigbee parametes configuration]:\n"
            f"       ├── Heartbeat interval:  {heartbeat} sec. (default: 14400)\n"
            f"       ├── Pairing timeout:     {pairing_timeout} sec. (default: 180)\n"
            f"       ├── Rejoin interval:     {rejoin_interval} sec. (default: 180)\n"
            f"       ├── Poll interval:       {poll_interval} ms. (default: 5000)\n"
            f"       ├── Fast poll time:      {fast_poll_time} sec. (default: 30)\n"
            f"       ├── Max failed polls:    {max_failed_polls} time(s) (default: 4)\n"
            f"       ├── Rejoin by MCU msg:   {rejoin_mcu_str}\n"
            f"       └── Max rejoin times:    {max_rejoin_times} time(s) (default: 1)"
        )

    # (Query DP data) ---
    if cmd_byte == 0x28:
        if len(data_bytes) == 0:
            output_lines.append("  └─ [Request DP statuses]: gateway requests ALL data points for the device")
        else:
            requested_dps = [f"DP_{b}" for b in data_bytes]
            str_requested = ", ".join(requested_dps)
            output_lines.append(f"  └─ [Request DP statuses]: gateway requests specific ID -> {str_requested}")

    # (Set wake-up waiting time) ---
    if cmd_byte == 0x2B:
        wakeup_results = parse_cmd_2B_data(data_bytes, current_port_role)
        if wakeup_results:
            output_lines.append("  └─ [Analysis of wake-up latency]:")
            for wakeup_line in wakeup_results:
                output_lines.append(f"       └── {wakeup_line}")

    # (Configure GPIO pins) ---
    if cmd_byte == 0x36 and data_bytes:
        gpio_results = parse_gpio_36_data(data_bytes, current_port_role)
        if gpio_results:
            output_lines.append("  └─ [Configuration analysis GPIO]:")
            for gpio_line in gpio_results:
                output_lines.append(f"       ├── {gpio_line}")
            output_lines[-1] = output_lines[-1].replace("├──", "└──")

    # (Read GPIO level) ---
    if cmd_byte == 0x37 and data_bytes:
        gpio_results = parse_gpio_37_data(data_bytes, current_port_role)
        if gpio_results:
            output_lines.append("  └─ [Analysis of GPIO Level Reading]:")
            for gpio_line in gpio_results:
                output_lines.append(f"       ├── {gpio_line}")
            output_lines[-1] = output_lines[-1].replace("├──", "└──")

    # (Control GPIO output) ---
    if cmd_byte == 0x38 and data_bytes:
        gpio_results = parse_gpio_38_data(data_bytes, current_port_role)
        if gpio_results:
            output_lines.append("  └─ [Analysis of GPIO Output Control]:")
            for gpio_line in gpio_results:
                output_lines.append(f"       ├── {gpio_line}")
            output_lines[-1] = output_lines[-1].replace("├──", "└──")

    # (Sync GPIO interrupt) ---
    if cmd_byte == 0x39:
        gpio_results = parse_gpio_39_data(data_bytes, current_port_role)
        if gpio_results:
            output_lines.append("  └─ [Analysis of GPIO Interrupt Handling]:")
            for gpio_line in gpio_results:
                output_lines.append(f"       └── {gpio_line}")

    # (Sync weather information) ---
    if cmd_byte == 0x3B and data_bytes:
        weather_results = parse_cmd_3B_data(data_bytes)
        if weather_results:
            output_lines.append("  └─ [Analysis of weather data and geolocation]:")
            for w_line in weather_results:
                output_lines.append(f"       ├── {w_line}")
            output_lines[-1] = output_lines[-1].replace("├──", "└──")

    # output very large string to console
    print("\n".join(output_lines))


def process_buffer(rx_buffer, port_name):
    while True:
        first_idx = rx_buffer.find(HEADER)
        if first_idx == -1:
            break

        next_idx = rx_buffer.find(HEADER, first_idx + len(HEADER))
        if next_idx == -1:
            break

        if first_idx > 0:
            del rx_buffer[:first_idx]
            next_idx -= first_idx

        packet = rx_buffer[:next_idx]
        del rx_buffer[:next_idx]

        print_packet(port_name, packet)


def read_from_port(port_name):
    print(f"[*] Start opening {port_name}...")

    try:
        ser = serial.Serial(
            port=port_name,
            baudrate=BAUDRATE,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.1,
        )
    except serial.SerialException as e:
        print(f"[!] Error opening port {port_name}: {e}")
        return

    rx_buffer = bytearray()

    try:
        while True:
            waiting_bytes = ser.in_waiting
            if waiting_bytes > 0:
                data = ser.read(waiting_bytes)
                rx_buffer.extend(data)
                process_buffer(rx_buffer, port_name)

            time.sleep(0.001)

    except KeyboardInterrupt:
        print(f"[-] Ending handling {port_name}...")
    finally:
        ser.close()
        print(f"[ ] Port {port_name} closed.")


if __name__ == "__main__":
    print("[*] To exit tap Ctrl+C.")

    thread1 = threading.Thread(target=read_from_port, args=(PORT_1,), daemon=True)
    thread2 = threading.Thread(target=read_from_port, args=(PORT_2,), daemon=True)

    thread1.start()
    thread2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] stopping...")
