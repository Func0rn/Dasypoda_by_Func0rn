# -*- coding: utf-8 -*-
"""
Sweyntooth Socket Bridge (Python 2.7)
使用原生 Socket 代替 Flask，减少 Python 2.7 环境下的依赖问题。
"""

import os
import sys
import time
import binascii
import socket
import json
import traceback

# 注入路径以加载 sweyntooth 库
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, 'libs'))

from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import raw

# BLESMPServer - 配对/加密状态机
try:
    import BLESMPServer
    HAS_SMP_SERVER = True
except ImportError:
    HAS_SMP_SERVER = False

# AES 加密库
try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False

# 全局状态
driver = None
smp_initialized = False

def handle_client(conn):
    global driver, smp_initialized
    try:
        data = conn.recv(4096)
        if not data:
            return
        
        request = json.loads(data.decode('utf-8'))
        cmd = request.get('cmd')
        params = request.get('params', {})
        
        response = {"status": "error", "message": "Unknown command"}
        
        if cmd == 'init':
            port = params.get('port', 'COM1')
            baudrate = params.get('baudrate', '115200')
            if driver:
                driver.close()
            driver = NRF52Dongle(port, baudrate)
            response = {"status": "success", "message": "Driver initialized"}
            
        elif cmd == 'send':
            if not driver:
                response = {"status": "error", "message": "Driver not initialized"}
            else:
                data_hex = params.get('data')
                raw_data = binascii.unhexlify(data_hex)
                driver.raw_send(raw_data)
                response = {"status": "success"}

        elif cmd == 'construct_and_send':
            if not driver:
                response = {"status": "error", "message": "Driver not initialized"}
            else:
                layer = params.get('layer')
                payload_hex = params.get('payload', '')
                payload = binascii.unhexlify(payload_hex) if payload_hex else b''
                access_address = params.get('access_address', 0x9a328370)
                
                pkt = BTLE(access_addr=access_address) / BTLE_DATA()
                
                if layer == 'LL_VERSION_IND':
                    pkt = pkt / CtrlPDU() / LL_VERSION_IND(version='4.2')
                elif layer == 'LL_FEATURE_REQ':
                    pkt = pkt / CtrlPDU() / LL_FEATURE_REQ(feature_set='le_encryption+le_data_len_ext')
                elif layer == 'LL_FEATURE_RSP':
                    pkt = pkt / CtrlPDU() / LL_FEATURE_RSP(feature_set='le_encryption+le_data_len_ext')
                elif layer == 'LL_LENGTH_REQ':
                    pkt = pkt / CtrlPDU() / LL_LENGTH_REQ(max_tx_bytes=251, max_rx_bytes=251)
                elif layer == 'LL_LENGTH_RSP':
                    pkt = pkt / CtrlPDU() / LL_LENGTH_RSP(max_tx_bytes=251, max_rx_bytes=251)
                elif layer == 'ATT_MTU_REQ':
                    pkt = pkt / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
                elif layer == 'TERMINATE':
                    pkt = pkt / CtrlPDU() / LL_TERMINATE_IND()
                elif layer == 'SCAN_REQ':
                    master_addr = params.get('master_address')
                    target_addr = params.get('target_address')
                    slave_type = params.get('slave_addr_type', 0)
                    pkt = BTLE() / BTLE_ADV(RxAdd=slave_type) / BTLE_SCAN_REQ(ScanA=master_addr, AdvA=target_addr)
                elif layer == 'CONN_REQ':
                    master_addr = params.get('master_address')
                    target_addr = params.get('target_address')
                    slave_type = params.get('slave_addr_type', 0)
                    pkt = BTLE() / BTLE_ADV(RxAdd=slave_type, TxAdd=0) / BTLE_CONNECT_REQ(
                        InitA=master_addr, AdvA=target_addr, AA=access_address,
                        crc_init=0x179a9c, win_size=2, win_offset=1, interval=16,
                        latency=0, timeout=50, chM=0x1FFFFFFFFF, hop=5, SCA=0
                    )
                elif layer == 'WRAP_FUZZ':
                    fuzz_layer = params.get('fuzz_layer')
                    if fuzz_layer == 'LINK_LAYER':
                        pkt = pkt / CtrlPDU() / payload
                    elif fuzz_layer == 'L2CAP':
                        pkt = pkt / L2CAP_Hdr() / payload
                    elif fuzz_layer == 'ATT':
                        pkt = pkt / L2CAP_Hdr() / ATT_Hdr() / payload
                    elif fuzz_layer == 'SMP':
                        pkt = pkt / L2CAP_Hdr() / SM_Hdr() / payload
                    else:
                        pkt = pkt / payload
                
                driver.send(pkt)
                response = {"status": "success"}

        elif cmd == 'smp_command':
            # 包装 BLESMPServer 的功能
            if not HAS_SMP_SERVER:
                response = {"status": "error", "message": "BLESMPServer not installed"}
            else:
                sub_cmd = params.get('sub_cmd')
                if sub_cmd == 'init':
                    if not smp_initialized:
                        BLESMPServer.configure_connection(
                            params.get('master_address'),
                            params.get('target_address'),
                            params.get('slave_addr_type', 0),
                            params.get('io_capability', 0x03),
                            params.get('auth_request', 0x01)
                        )
                        smp_initialized = True
                    response = {"status": "success"}
                elif sub_cmd == 'pairing_request':
                    data = BLESMPServer.pairing_request()
                    response = {"status": "success", "data": binascii.hexlify(data).decode('ascii')}
                elif sub_cmd == 'get_ltk':
                    ltk = BLESMPServer.get_ltk()
                    response = {"status": "success", "ltk": binascii.hexlify(ltk).decode('ascii') if ltk else None}
                elif sub_cmd == 'send_hci':
                    hci_data = binascii.unhexlify(params.get('data'))
                    resp = BLESMPServer.send_hci(hci_data)
                    response = {"status": "success", "data": binascii.hexlify(resp).decode('ascii') if resp else None}

        elif cmd == 'crypto_command':
            # 包装 AES 加密功能
            if not HAS_CRYPTO:
                response = {"status": "error", "message": "Crypto library not installed"}
            else:
                sub_cmd = params.get('sub_cmd')
                key = binascii.unhexlify(params.get('key'))
                if sub_cmd == 'e':
                    plaintext = binascii.unhexlify(params.get('plaintext'))
                    aes = AES.new(key, AES.MODE_ECB)
                    ciphertext = aes.encrypt(plaintext)
                    response = {"status": "success", "data": binascii.hexlify(ciphertext).decode('ascii')}

        elif cmd == 'recv' or cmd == 'recv_and_parse':
            if not driver:
                response = {"status": "error", "message": "Driver not initialized"}
            else:
                timeout = float(params.get('timeout', 0.1))
                start_time = time.time()
                received_data = None
                while (time.time() - start_time) < timeout:
                    received_data = driver.raw_receive()
                    if received_data:
                        break
                    time.sleep(0.001)
                
                if received_data:
                    layers = []
                    try:
                        pkt = BTLE(received_data)
                        # 识别包中包含的 Scapy 层
                        possible_layers = [
                            BTLE, BTLE_DATA, BTLE_ADV, BTLE_SCAN_REQ, BTLE_SCAN_RSP, BTLE_ADV_IND,
                            BTLE_EMPTY_PDU,  # 空 PDU
                            LL_VERSION_IND, LL_FEATURE_REQ, LL_FEATURE_RSP, LL_LENGTH_REQ, LL_LENGTH_RSP,
                            LL_UNKNOWN_RSP,  # 未知响应
                            LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_REQ, LL_START_ENC_RSP,
                            LL_TERMINATE_IND,  # 断开连接
                            ATT_Exchange_MTU_Request, ATT_Exchange_MTU_Response, SM_Security_Request,
                            L2CAP_Hdr, ATT_Hdr, SM_Hdr
                        ]
                        for layer_cls in possible_layers:
                            if layer_cls in pkt:
                                layers.append(layer_cls.__name__)
                    except:
                        pass

                    response = {
                        "status": "success",
                        "data": binascii.hexlify(received_data).decode('ascii'),
                        "layers": layers
                    }
                else:
                    response = {"status": "timeout", "data": None}
                    
        elif cmd == 'close':
            if driver:
                driver.close()
                driver = None
            response = {"status": "success"}
            
        conn.sendall(json.dumps(response).encode('utf-8'))
    except Exception as e:
        err_msg = traceback.format_exc()
        print(err_msg)
        try:
            conn.sendall(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
        except:
            pass
    finally:
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 5000))
    server.listen(5)
    print("Socket Bridge started on 127.0.0.1:5000")
    
    try:
        while True:
            conn, addr = server.accept()
            handle_client(conn)
    except KeyboardInterrupt:
        print("Stopping bridge...")
    finally:
        server.close()

if __name__ == '__main__':
    main()