#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
BLE Scanner and GATT/ATT Service Mapper
蓝牙低功耗设备扫描器和GATT/ATT服务测绘工具

基于 sweyntooth 框架实现，功能:
1. 扫描并连接指定蓝牙设备
2. 枚举GATT服务、特征和描述符
3. 抓包持久化到pcap文件
4. 收集协议交互数据用于动态生成fuzz脚本

使用方法:
    python ble_scanner_mapper.py --address 80:ea:ca:80:00:01 [--port COM3]
"""

import os
import sys
import platform
import json
import datetime
import binascii
from time import sleep

# ============= Sweyntooth 库路径配置 =============
# 复用sweyntooth的目录结构
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BOOFUZZ_DIR = os.path.dirname(SCRIPT_DIR)
SWEYNTOOTH_DIR = os.path.join(BOOFUZZ_DIR, 'utils', 'sweyntooth')
SWEYNTOOTH_LIBS_DIR = os.path.join(SWEYNTOOTH_DIR, 'libs')

sys.path.insert(0, SWEYNTOOTH_DIR)
sys.path.insert(0, SWEYNTOOTH_LIBS_DIR)

# Sweyntooth imports (复用现有库)
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import wrpcap, raw
from timeout_lib import start_timeout, disable_timeout, update_timeout

# 自动重置颜色
colorama.init(autoreset=True)

# ============= 配置参数 (与sweyntooth保持一致) =============
DEFAULT_MASTER_ADDRESS = '5d:36:ac:90:0b:22'
ACCESS_ADDRESS = 0x9a328370

# GATT/ATT 操作码定义
ATT_OPCODES = {
    0x01: 'ATT_ERROR_RSP',
    0x02: 'ATT_EXCHANGE_MTU_REQ',
    0x03: 'ATT_EXCHANGE_MTU_RSP',
    0x04: 'ATT_FIND_INFO_REQ',
    0x05: 'ATT_FIND_INFO_RSP',
    0x06: 'ATT_FIND_BY_TYPE_VALUE_REQ',
    0x07: 'ATT_FIND_BY_TYPE_VALUE_RSP',
    0x08: 'ATT_READ_BY_TYPE_REQ',
    0x09: 'ATT_READ_BY_TYPE_RSP',
    0x0A: 'ATT_READ_REQ',
    0x0B: 'ATT_READ_RSP',
    0x0C: 'ATT_READ_BLOB_REQ',
    0x0D: 'ATT_READ_BLOB_RSP',
    0x10: 'ATT_READ_BY_GROUP_TYPE_REQ',
    0x11: 'ATT_READ_BY_GROUP_TYPE_RSP',
    0x12: 'ATT_WRITE_REQ',
    0x13: 'ATT_WRITE_RSP',
    0x52: 'ATT_WRITE_CMD',
    0x1B: 'ATT_HANDLE_VALUE_NTF',
    0x1D: 'ATT_HANDLE_VALUE_IND',
}

# 标准GATT服务UUID
GATT_SERVICE_UUIDS = {
    0x1800: 'Generic Access',
    0x1801: 'Generic Attribute',
    0x180A: 'Device Information',
    0x180F: 'Battery Service',
    0x180D: 'Heart Rate',
    0x1810: 'Blood Pressure',
    0x1816: 'Cycling Speed and Cadence',
    0x181A: 'Environmental Sensing',
    0x181C: 'User Data',
}

# GATT特征UUID
GATT_CHAR_UUIDS = {
    0x2A00: 'Device Name',
    0x2A01: 'Appearance',
    0x2A04: 'Peripheral Preferred Connection Parameters',
    0x2A05: 'Service Changed',
    0x2A19: 'Battery Level',
    0x2A29: 'Manufacturer Name String',
    0x2A24: 'Model Number String',
    0x2A25: 'Serial Number String',
    0x2A26: 'Firmware Revision String',
    0x2A27: 'Hardware Revision String',
    0x2A28: 'Software Revision String',
}


class BLEServiceMapper:
    """
    BLE服务测绘器 - 基于sweyntooth框架
    
    收集的数据将用于动态生成各协议层的fuzz脚本
    """
    
    def __init__(self, serial_port, advertiser_address, master_address=DEFAULT_MASTER_ADDRESS):
        self.serial_port = serial_port
        self.advertiser_address = advertiser_address.lower()
        self.master_address = master_address
        self.access_address = ACCESS_ADDRESS
        self.driver = None
        self.connected = False
        self.connecting = False
        self.slave_addr_type = 0
        self.run_script = True
        
        # ============= 协议交互数据收集 =============
        # Link Layer 数据
        self.ll_version = None
        self.ll_features = None
        self.ll_length_params = None
        
        # L2CAP 数据
        self.l2cap_mtu = 23  # 默认BLE MTU
        
        # ATT/GATT 数据
        self.services = []
        self.characteristics = []
        self.descriptors = []
        self.att_handles = {}  # handle -> {type, uuid, properties, value}
        
        # SMP 数据
        self.smp_pairing_supported = False
        self.smp_io_cap = None
        self.smp_auth_req = None
        
        # GAP 数据
        self.device_name = None
        self.appearance = None
        self.adv_data = None
        self.scan_rsp_data = None
        
        # 原始数据包记录
        self.captured_packets = []
        self.protocol_interactions = []  # 记录所有协议交互用于回放
        
        # 当前枚举状态
        self.current_handle = 0x0001
        self.enum_state = 'idle'
        
        # 输出目录配置
        self.output_dir = os.path.join(SCRIPT_DIR, 'scan_results')
        
    def start(self):
        """初始化驱动 (sweyntooth风格)"""
        print(Fore.YELLOW + f'Serial port: {self.serial_port}')
        print(Fore.YELLOW + f'Advertiser Address: {self.advertiser_address.upper()}')
        
        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 使用sweyntooth的驱动初始化方式
        self.driver = NRF52Dongle(
            self.serial_port, '115200', 
            logs_pcap=True,
            pcap_filename=os.path.join(self.output_dir, f'capture_{self.advertiser_address.replace(":", "")}.pcap')
        )
        
    def close(self):
        """关闭驱动"""
        if self.driver:
            self.driver.save_pcap()
            self.driver.close()
            
    def save_captured_packets(self):
        """[已由driver.save_pcap()处理]"""
        pass
            
    def save_scan_result(self):
        """保存完整的扫描结果到JSON文件 - 用于动态生成fuzz脚本"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scan_result_{self.advertiser_address.replace(":", "")}_{timestamp}.json'
        filepath = os.path.join(self.output_dir, filename)
        
        # 完整的扫描数据结构 - 包含所有层的信息
        data = {
            'meta': {
                'target_address': self.advertiser_address,
                'scan_time': timestamp,
                'master_address': self.master_address,
                'access_address': hex(self.access_address),
            },
            'gap': {
                'device_name': self.device_name,
                'appearance': self.appearance,
                'adv_data_hex': self.adv_data.hex() if self.adv_data else None,
                'scan_rsp_hex': self.scan_rsp_data.hex() if self.scan_rsp_data else None,
            },
            'link_layer': {
                'version': self.ll_version,
                'features': self.ll_features,
                'length_params': self.ll_length_params,
                'slave_addr_type': self.slave_addr_type,
            },
            'l2cap': {
                'mtu': self.l2cap_mtu,
            },
            'att': {
                'mtu': self.l2cap_mtu,
                'handles': self.att_handles,
            },
            'gatt': {
                'services': self.services,
                'characteristics': self.characteristics,
                'descriptors': self.descriptors,
            },
            'smp': {
                'pairing_supported': self.smp_pairing_supported,
                'io_cap': self.smp_io_cap,
                'auth_req': self.smp_auth_req,
            },
            'protocol_interactions': self.protocol_interactions,
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
        print(Fore.GREEN + f'Scan result saved to: {filepath}')
        return filepath
    
    def record_interaction(self, direction, layer, pkt_type, data_hex, parsed=None):
        """记录协议交互"""
        self.protocol_interactions.append({
            'direction': direction,  # 'TX' or 'RX'
            'layer': layer,          # 'LL', 'L2CAP', 'ATT', 'SMP', 'GAP'
            'type': pkt_type,
            'data_hex': data_hex,
            'parsed': parsed,
        })

    def run_scan_and_map(self, timeout=30):
        """
        运行扫描和服务映射 - sweyntooth风格的状态机
        收集完整的协议交互数据用于生成fuzz脚本
        """
        self.start()
        
        # 发送扫描请求 (sweyntooth模式)
        scan_req = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.advertiser_address)
        self.driver.send(scan_req)
        
        # 设置超时 (sweyntooth模式)
        def crash_timeout():
            print(Fore.RED + f"No advertisement from {self.advertiser_address.upper()} received")
            self.run_script = False
            
        def scan_timeout_handler():
            if not self.connected:
                scan_req = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
                    ScanA=self.master_address,
                    AdvA=self.advertiser_address)
                self.driver.send(scan_req)
            start_timeout('scan_timeout', 2, scan_timeout_handler)
            
        start_timeout('scan_timeout', 2, scan_timeout_handler)
        start_timeout('crash_timeout', timeout, crash_timeout)
        
        phase = 'scanning'
        none_count = 0
        
        print(Fore.YELLOW + f'Waiting advertisements from {self.advertiser_address}')
        
        # sweyntooth风格的主循环
        while self.run_script:
            pkt = None
            data = self.driver.raw_receive()
            
            if data:
                pkt = BTLE(data)
                
                if pkt is None:
                    none_count += 1
                    if none_count >= 4:
                        print(Fore.RED + 'NRF52 Dongle not detected')
                        break
                    continue
                
                # 记录接收到的数据包
                if BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
                    update_timeout('scan_timeout')
                    print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
                
                # =============== 广播阶段 ===============
                if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and \
                   pkt.AdvA == self.advertiser_address and not self.connecting:
                    
                    disable_timeout('crash_timeout')
                    update_timeout('scan_timeout')
                    self.connecting = True
                    self.slave_addr_type = pkt.TxAdd
                    
                    # 收集GAP广播数据
                    if hasattr(pkt, 'data'):
                        self.adv_data = raw(pkt.data) if pkt.data else None
                    if BTLE_SCAN_RSP in pkt and hasattr(pkt[BTLE_SCAN_RSP], 'data'):
                        self.scan_rsp_data = raw(pkt[BTLE_SCAN_RSP].data) if pkt[BTLE_SCAN_RSP].data else None
                        
                    self.record_interaction('RX', 'GAP', 'ADV', data.hex(), {'addr_type': self.slave_addr_type})
                    
                    print(Fore.GREEN + f'{self.advertiser_address.upper()}: {pkt.summary()[7:]} Detected')
                    
                    # 发送连接请求 (sweyntooth模式)
                    conn_request = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                        InitA=self.master_address,
                        AdvA=self.advertiser_address,
                        AA=self.access_address,
                        crc_init=0x179a9c,
                        win_size=2,
                        win_offset=1,
                        interval=16,
                        latency=0,
                        timeout=50,
                        chM=0x1FFFFFFFFF,
                        hop=5,
                        SCA=0,
                    )
                    self.driver.send(conn_request)
                    self.record_interaction('TX', 'LL', 'CONNECT_REQ', raw(conn_request).hex())
                    phase = 'connecting'
                    
                # =============== 连接建立阶段 ===============
                elif BTLE_DATA in pkt and self.connecting:
                    self.connecting = False
                    self.connected = True
                    print(Fore.GREEN + 'Slave Connected (L2Cap channel established)')
                    
                    # 发送版本指示 (sweyntooth模式)
                    version_ind = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
                    self.driver.send(version_ind)
                    self.record_interaction('TX', 'LL', 'VERSION_IND', raw(version_ind).hex())
                    phase = 'version'
                    
                # =============== Link Layer 协商 ===============
                elif LL_VERSION_IND in pkt:
                    self.ll_version = {
                        'version': pkt[LL_VERSION_IND].version,
                        'company': pkt[LL_VERSION_IND].Company,
                        'subversion': pkt[LL_VERSION_IND].subversion
                    }
                    self.record_interaction('RX', 'LL', 'VERSION_IND', data.hex(), self.ll_version)
                    
                    # 发送长度请求
                    length_req = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                        max_tx_bytes=251, max_rx_bytes=251)
                    self.driver.send(length_req)
                    self.record_interaction('TX', 'LL', 'LENGTH_REQ', raw(length_req).hex())
                    phase = 'length'
                    
                elif LL_LENGTH_RSP in pkt:
                    self.ll_length_params = {
                        'max_rx_bytes': pkt[LL_LENGTH_RSP].max_rx_bytes,
                        'max_tx_bytes': pkt[LL_LENGTH_RSP].max_tx_bytes,
                    }
                    self.record_interaction('RX', 'LL', 'LENGTH_RSP', data.hex(), self.ll_length_params)
                    self._send_mtu_request()
                    phase = 'mtu'
                    
                elif LL_UNKNOWN_RSP in pkt:
                    self.record_interaction('RX', 'LL', 'UNKNOWN_RSP', data.hex())
                    self._send_mtu_request()
                    phase = 'mtu'
                    
                elif LL_FEATURE_RSP in pkt:
                    self.ll_features = str(pkt[LL_FEATURE_RSP].feature_set)
                    self.record_interaction('RX', 'LL', 'FEATURE_RSP', data.hex())
                    
                # =============== ATT/GATT 协商 ===============
                elif ATT_Exchange_MTU_Response in pkt:
                    self.l2cap_mtu = pkt[ATT_Exchange_MTU_Response].mtu
                    self.record_interaction('RX', 'ATT', 'MTU_RSP', data.hex(), {'mtu': self.l2cap_mtu})
                    print(Fore.GREEN + f'MTU negotiated: {self.l2cap_mtu}')
                    
                    # 开始服务发现
                    self._send_read_by_group_type_request()
                    phase = 'discover_services'
                    
                elif ATT_Read_By_Group_Type_Response in pkt:
                    resp = pkt[ATT_Read_By_Group_Type_Response]
                    services = self._parse_services_response(bytes(resp))
                    self.record_interaction('RX', 'ATT', 'READ_BY_GROUP_TYPE_RSP', data.hex(), {'services': services})
                    
                    if services:
                        self.services.extend(services)
                        last_handle = services[-1]['end_handle']
                        if last_handle < 0xFFFF:
                            self._send_read_by_group_type_request(last_handle + 1)
                        else:
                            print(Fore.GREEN + f'Service discovery complete. Found {len(self.services)} services')
                            # 继续发现特征
                            if self.services:
                                self._discover_characteristics()
                            else:
                                phase = 'complete'
                                break
                                
                elif ATT_Read_By_Type_Response in pkt:
                    self.record_interaction('RX', 'ATT', 'READ_BY_TYPE_RSP', data.hex())
                    # TODO: 解析特征
                    
                elif ATT_Error_Response in pkt:
                    err = pkt[ATT_Error_Response]
                    self.record_interaction('RX', 'ATT', 'ERROR_RSP', data.hex(), {'ecode': err.ecode})
                    
                    if err.ecode == 0x0a:  # Attribute Not Found
                        if phase == 'discover_services':
                            print(Fore.GREEN + f'Service discovery complete. Found {len(self.services)} services')
                            if self.services:
                                self._discover_characteristics()
                            else:
                                phase = 'complete'
                                break
                        elif phase == 'discover_chars':
                            print(Fore.GREEN + f'Characteristic discovery complete.')
                            phase = 'complete'
                            break
                            
                # =============== SMP探测 ===============
                elif SM_Pairing_Response in pkt:
                    self.smp_pairing_supported = True
                    self.smp_io_cap = pkt[SM_Pairing_Response].iocap
                    self.smp_auth_req = pkt[SM_Pairing_Response].authentication
                    self.record_interaction('RX', 'SMP', 'PAIRING_RSP', data.hex())
                    
            sleep(0.01)
            
        disable_timeout('scan_timeout')
        disable_timeout('crash_timeout')
        
        # 打印发现的服务
        self._print_results()
        
        # 保存结果
        return self.save_scan_result()
    
    def _send_mtu_request(self, mtu=247):
        """发送MTU交换请求"""
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / \
              ATT_Exchange_MTU_Request(mtu=mtu)
        self.driver.send(pkt)
        self.record_interaction('TX', 'ATT', 'MTU_REQ', raw(pkt).hex())
        print(Fore.CYAN + f'MTU Exchange Request sent (MTU={mtu})')
        
    def _send_read_by_group_type_request(self, start_handle=0x0001, end_handle=0xFFFF, uuid=0x2800):
        """发送Read By Group Type请求 (发现主服务)"""
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / \
              ATT_Read_By_Group_Type_Request(start=start_handle, end=end_handle, uuid=uuid)
        self.driver.send(pkt)
        self.record_interaction('TX', 'ATT', 'READ_BY_GROUP_TYPE_REQ', raw(pkt).hex())
        
    def _discover_characteristics(self):
        """发现服务的特征"""
        if self.services:
            svc = self.services[0]
            pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / \
                  ATT_Read_By_Type_Request(start=svc['start_handle'], end=svc['end_handle'], uuid=0x2803)
            self.driver.send(pkt)
            self.record_interaction('TX', 'ATT', 'READ_BY_TYPE_REQ', raw(pkt).hex())
    
    def _parse_services_response(self, data):
        """解析Read By Group Type响应"""
        if len(data) < 2:
            return []
            
        length = data[0]
        services = []
        offset = 1
        
        while offset + length <= len(data):
            if length == 6:  # 16-bit UUID
                start_handle = data[offset] | (data[offset + 1] << 8)
                end_handle = data[offset + 2] | (data[offset + 3] << 8)
                uuid = data[offset + 4] | (data[offset + 5] << 8)
                services.append({
                    'start_handle': start_handle,
                    'end_handle': end_handle,
                    'uuid': f'0x{uuid:04X}',
                    'uuid_int': uuid,
                    'name': GATT_SERVICE_UUIDS.get(uuid, 'Unknown')
                })
            elif length == 20:  # 128-bit UUID
                start_handle = data[offset] | (data[offset + 1] << 8)
                end_handle = data[offset + 2] | (data[offset + 3] << 8)
                uuid_bytes = data[offset + 4:offset + 20]
                uuid_str = '-'.join([uuid_bytes[i:i+2].hex() for i in range(0, 16, 2)][::-1])
                services.append({
                    'start_handle': start_handle,
                    'end_handle': end_handle,
                    'uuid': uuid_str,
                    'uuid_int': None,
                    'name': 'Custom Service'
                })
            offset += length
            
        return services
    
    def _print_results(self):
        """打印扫描结果"""
        print(Fore.YELLOW + '\n' + '=' * 60)
        print(Fore.YELLOW + 'SCAN RESULTS')
        print(Fore.YELLOW + '=' * 60)
        
        print(Fore.CYAN + f'\nTarget: {self.advertiser_address.upper()}')
        
        if self.ll_version:
            print(Fore.CYAN + f"LL Version: {self.ll_version['version']} (Company: {self.ll_version['company']})")
            
        print(Fore.CYAN + f'ATT MTU: {self.l2cap_mtu}')
        print(Fore.CYAN + f'SMP Pairing: {"Supported" if self.smp_pairing_supported else "Not tested"}')
        
        print(Fore.YELLOW + f'\nDiscovered {len(self.services)} Services:')
        for svc in self.services:
            print(Fore.GREEN + f"  [{svc['uuid']}] {svc['name']}")
            print(Fore.WHITE + f"    Handle Range: 0x{svc['start_handle']:04X} - 0x{svc['end_handle']:04X}")
            
        print(Fore.YELLOW + f'\nProtocol Interactions: {len(self.protocol_interactions)} recorded')
        print(Fore.YELLOW + '=' * 60)


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BLE Scanner and Service Mapper')
    parser.add_argument('--port', '-p', help='Serial port (e.g., COM3, /dev/ttyACM0)')
    parser.add_argument('--address', '-a', required=True, help='Target BLE device address (e.g., 80:ea:ca:80:00:01)')
    parser.add_argument('--timeout', '-t', type=int, default=30, help='Scan timeout in seconds')
    
    args = parser.parse_args()
    
    # 自动检测串口
    serial_port = args.port
    if serial_port is None:
        if platform.system() == 'Linux':
            serial_port = '/dev/ttyACM0'
        elif platform.system() == 'Windows':
            serial_port = 'COM3'
        else:
            print(Fore.RED + 'Please specify serial port with --port')
            sys.exit(1)
            
    mapper = BLEServiceMapper(serial_port, args.address)
    
    try:
        service_map_file = mapper.run_scan_and_map(args.timeout)
        print(Fore.GREEN + f'\nService mapping complete!')
        print(Fore.GREEN + f'Results saved to: {service_map_file}')
    except KeyboardInterrupt:
        print(Fore.YELLOW + '\nScan interrupted by user')
    finally:
        mapper.close()


if __name__ == '__main__':
    main()
