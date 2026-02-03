"""BLE Connection for Boofuzz - 基于 Sweyntooth 的多层 BLE Fuzzing 连接

设计原则:
1. 完整实现 BLE 连接状态机 (参考 Sweyntooth 脚本模式)
2. 支持多层 Fuzz 目标 (Link Layer / L2CAP / ATT / SMP)
3. 自动处理协议握手，让 Boofuzz 专注于变异数据注入
4. 集成 BLESMPServer 实现完整配对/加密支持
"""

import time
import struct
import json
import socket
from enum import Enum, auto
from threading import Thread, Event
from typing import Optional, Callable, Dict, Any
from binascii import hexlify, unhexlify

from boofuzz.connections import itarget_connection
from boofuzz.exception import BoofuzzTargetConnectionFailedError

# Sweyntooth 协议栈导入 (仅用于本地驱动模式)
try:
    from ..utils.sweyntooth.drivers.NRF52_dongle import NRF52Dongle
    from ..utils.sweyntooth.libs.scapy.layers.bluetooth4LE import (
        BTLE, BTLE_ADV, BTLE_DATA, BTLE_SCAN_REQ, BTLE_SCAN_RSP,
        BTLE_ADV_IND, BTLE_CONNECT_REQ, BTLE_EMPTY_PDU, CtrlPDU,
        LL_VERSION_IND, LL_FEATURE_REQ, LL_FEATURE_RSP,
        LL_LENGTH_REQ, LL_LENGTH_RSP, LL_UNKNOWN_RSP,
        LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_REQ, LL_START_ENC_RSP,
        LL_TERMINATE_IND, LL_REJECT_IND
    )
    from ..utils.sweyntooth.libs.scapy.layers.bluetooth import (
        L2CAP_Hdr, ATT_Hdr, SM_Hdr, HCI_Hdr, HCI_ACL_Hdr,
        ATT_Exchange_MTU_Request, ATT_Exchange_MTU_Response,
        SM_Pairing_Request, SM_Pairing_Response, SM_Failed,
        SM_Random, SM_Security_Request, SM_Public_Key, SM_Confirm
    )
    from ..utils.sweyntooth.libs.scapy.utils import raw
    HAS_LOCAL_DRIVER = True
except ImportError:
    HAS_LOCAL_DRIVER = False
    # 如果本地导入失败，定义 Dummy 类或使用字符串标识符，因为在桥接模式下不需要本地 Scapy 对象
    BTLE = BTLE_DATA = BTLE_SCAN_RSP = BTLE_ADV_IND = None
    LL_VERSION_IND = LL_FEATURE_RSP = LL_FEATURE_REQ = LL_LENGTH_REQ = LL_LENGTH_RSP = LL_UNKNOWN_RSP = None
    LL_TERMINATE_IND = LL_REJECT_IND = LL_ENC_RSP = LL_START_ENC_RSP = None
    ATT_Exchange_MTU_Response = SM_Hdr = SM_Security_Request = SM_Pairing_Response = None
    SM_Public_Key = SM_Confirm = SM_Random = SM_Failed = L2CAP_Hdr = ATT_Hdr = None
    def raw(x): return x

# BLESMPServer - 配对/加密状态机 (可选)
try:
    import BLESMPServer
    HAS_SMP_SERVER = True
except ImportError:
    HAS_SMP_SERVER = False
    print("[BLE] 警告: BLESMPServer 未安装，加密功能不可用")
    print("[BLE] 安装方法: cd boofuzz/utils/sweyntooth/libs/smp_server && python setup.py install")

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
        print("[BLE] 警告: PyCryptodome 未安装，加密功能不可用")
        print("[BLE] 安装方法: pip install pycryptodome")


class BLEFuzzLayer(Enum):
    """Fuzz 目标层"""
    LINK_LAYER = auto()      # Link Layer 控制包 (LL_*)
    L2CAP = auto()           # L2CAP 层
    ATT = auto()             # ATT/GATT 层
    SMP = auto()             # Security Manager Protocol
    RAW = auto()             # 原始字节 (完全自定义)


class BLEConnectionState(Enum):
    """BLE 连接状态"""
    IDLE = auto()
    SCANNING = auto()
    CONNECTING = auto()
    CONNECTED = auto()       # L2CAP 通道已建立
    FEATURE_EXCHANGED = auto()
    READY = auto()           # 可以开始 Fuzz (无加密)
    PAIRING = auto()         # 配对过程中
    ENCRYPTED = auto()       # 已加密，可以 Fuzz
    DISCONNECTED = auto()
    ERROR = auto()


class BLEIOCapability:
    """BLE IO 能力 (SMP 配对方法选择)"""
    DISPLAY_ONLY = 0x00
    DISPLAY_YES_NO = 0x01
    KEYBOARD_ONLY = 0x02
    NO_INPUT_NO_OUTPUT = 0x03
    KEYBOARD_DISPLAY = 0x04


class BLEAuthReq:
    """BLE 认证请求标志"""
    NO_BONDING = 0x00
    BONDING = 0x01
    MITM = 0x04
    SC = 0x08               # LE Secure Connections
    KEYPRESS = 0x10
    # 常用组合
    LEGACY_PAIRING = BONDING
    SECURE_CONNECTIONS = SC | BONDING
    SC_MITM = SC | MITM | BONDING


class SMPConfig:
    """
    SMP 配对/加密配置
    
    参考 Sweyntooth 的 SMP 实现和蓝牙规范
    """
    def __init__(
        self,
        io_capability: int = BLEIOCapability.NO_INPUT_NO_OUTPUT,
        auth_request: int = BLEAuthReq.SECURE_CONNECTIONS,
        max_key_size: int = 16,
        initiator_key_dist: int = 0x07,  # EncKey + IdKey + Sign
        responder_key_dist: int = 0x07,
        pin_code: bytes = None
    ):
        self.io_capability = io_capability
        self.auth_request = auth_request
        self.max_key_size = max_key_size
        self.initiator_key_dist = initiator_key_dist
        self.responder_key_dist = responder_key_dist
        self.pin_code = pin_code or b'\x00' * 16
    
    @classmethod
    def just_works(cls):
        """Just Works 配对 (无 MITM 保护)"""
        return cls(
            io_capability=BLEIOCapability.NO_INPUT_NO_OUTPUT,
            auth_request=BLEAuthReq.BONDING
        )
    
    @classmethod
    def secure_connections(cls):
        """LE Secure Connections 配对"""
        return cls(
            io_capability=BLEIOCapability.DISPLAY_YES_NO,
            auth_request=BLEAuthReq.SECURE_CONNECTIONS
        )
    
    @classmethod
    def secure_connections_mitm(cls):
        """LE Secure Connections + MITM"""
        return cls(
            io_capability=BLEIOCapability.KEYBOARD_DISPLAY,
            auth_request=BLEAuthReq.SC_MITM
        )


class BLEConnection(itarget_connection.ITargetConnection):
    """
    基于 Sweyntooth 的 Boofuzz BLE 连接实现。
    
    支持多层 BLE Fuzzing:
    - LINK_LAYER: Fuzz LL 控制包 (LL_VERSION_IND, LL_FEATURE_REQ 等)
    - L2CAP: Fuzz L2CAP 层
    - ATT: Fuzz ATT/GATT 协议
    - SMP: Fuzz 安全管理协议
    
    Args:
        port: NRF52 Dongle 串口 (如 'COM3' 或 '/dev/ttyACM0')
        target_address: 目标设备 MAC 地址 (如 '80:ea:ca:80:00:01')
        fuzz_layer: 要 Fuzz 的协议层 (默认 ATT)
        master_address: 主机 MAC 地址 (默认自动生成)
        enable_encryption: 是否启用加密 (需要配对)
        auto_reconnect: 连接断开后是否自动重连
        connection_timeout: 连接超时时间 (秒)
        crash_timeout: 崩溃检测超时时间 (秒)
    """
    
    # 默认主机地址 (与 Sweyntooth 脚本保持一致)
    DEFAULT_MASTER_ADDRESS = '5d:36:ac:90:0b:22'
    DEFAULT_ACCESS_ADDRESS = 0x9a328370
    
    def __init__(
        self,
        port: str,
        target_address: str,
        fuzz_layer: BLEFuzzLayer = BLEFuzzLayer.ATT,
        master_address: str = None,
        enable_encryption: bool = False,
        smp_config: SMPConfig = None,
        auto_reconnect: bool = True,
        connection_timeout: float = 5.0,
        crash_timeout: float = 7.0,
        logs_pcap: bool = True,
        pcap_filename: str = None
    ):
        self._port = port
        self._target_address = target_address.lower()
        self._fuzz_layer = fuzz_layer
        self._master_address = master_address or self.DEFAULT_MASTER_ADDRESS
        self._enable_encryption = enable_encryption
        self._smp_config = smp_config or SMPConfig.just_works()
        self._auto_reconnect = auto_reconnect
        self._connection_timeout = connection_timeout
        self._crash_timeout = crash_timeout
        self._logs_pcap = logs_pcap
        self._pcap_filename = pcap_filename or f'ble_fuzz_{target_address.replace(":", "")}.pcap'
        
        # 硬件驱动 (本地或远程桥接)
        self._driver: Optional[NRF52Dongle] = None
        self._bridge_host = "127.0.0.1"
        self._bridge_port = 5000
        self._use_bridge = not HAS_LOCAL_DRIVER
        
        # 连接状态
        self._state = BLEConnectionState.IDLE
        self._access_address = self.DEFAULT_ACCESS_ADDRESS
        self._slave_addr_type = 0  # 0=Public, 1=Random
        
        # 协议状态标志
        self._version_received = False
        self._features_received = False
        self._length_received = False
        self._mtu_exchanged = False
        
        # 加密相关 (BLESMPServer 集成)
        self._conn_ltk = None           # Long Term Key
        self._conn_skd = None           # Session Key Diversifier
        self._conn_iv = None            # Initialization Vector
        self._conn_session_key = None   # 会话密钥 (SK)
        self._conn_tx_packet_counter = 0
        self._conn_rx_packet_counter = 0
        self._encryption_enabled = False
        self._pairing_procedure = False
        
        # L2CAP 分片重组
        self._fragment_start = False
        self._fragment_left = 0
        self._fragment_buffer = None
        
        # 后台接收线程
        self._recv_thread: Optional[Thread] = None
        self._stop_event = Event()
        self._recv_buffer = bytearray()
        
        # 回调
        self._on_crash_detected: Optional[Callable] = None
        self._on_pairing_complete: Optional[Callable] = None
        
        # 超时计时器
        self._last_rx_time = 0
        
        # SMP 服务器初始化标志
        self._smp_initialized = False
    
    def _call_bridge(self, cmd, params=None):
        """调用 Socket 桥接服务"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((self._bridge_host, self._bridge_port))
                request = {"cmd": cmd, "params": params or {}}
                s.sendall(json.dumps(request).encode('utf-8'))
                data = s.recv(4096)
                if not data:
                    return {"status": "error", "message": "No response from bridge"}
                return json.loads(data.decode('utf-8'))
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ==================== ITargetConnection 接口实现 ====================
    
    def open(self):
        """打开连接并建立 BLE 链路"""
        try:
            # 初始化硬件驱动
            if self._use_bridge:
                resp = self._call_bridge("init", {
                    "port": self._port,
                    "baudrate": "115200"
                })
                if resp.get("status") != "success":
                    raise BoofuzzTargetConnectionFailedError(f"无法初始化桥接服务: {resp.get('message')}")
            else:
                self._driver = NRF52Dongle(
                    self._port,
                    str(115200),
                    logs_pcap=self._logs_pcap,
                    pcap_filename=self._pcap_filename
                )
            
            # 启动后台接收线程
            self._stop_event.clear()
            self._recv_thread = Thread(target=self._receive_loop, daemon=True)
            self._recv_thread.start()
            
            # 建立 BLE 连接
            if not self._establish_connection():
                raise BoofuzzTargetConnectionFailedError(
                    f"无法连接到 BLE 设备: {self._target_address}"
                )
                
        except Exception as e:
            self.close()
            raise BoofuzzTargetConnectionFailedError(f"BLE 连接失败: {e}")
    
    def close(self):
        """关闭连接"""
        # 发送断开请求
        if (self._driver or self._use_bridge) and self._state in (
            BLEConnectionState.CONNECTED,
            BLEConnectionState.READY,
            BLEConnectionState.ENCRYPTED
        ):
            try:
                self._send_terminate()
            except:
                pass
        
        # 停止接收线程
        self._stop_event.set()
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=1.0)
        
        # 保存 pcap
        if self._driver and self._logs_pcap:
            try:
                self._driver.save_pcap()
            except:
                pass
        
        # 关闭驱动
        if self._use_bridge:
            try:
                self._call_bridge("close")
            except:
                pass
        elif self._driver:
            self._driver.close()
            self._driver = None
        
        self._state = BLEConnectionState.IDLE
    
    def send(self, data: bytes) -> int:
        """
        发送 Fuzz 数据。
        根据 fuzz_layer 设置，自动包装为对应协议层的包。
        """
        if self._state not in (BLEConnectionState.READY, BLEConnectionState.ENCRYPTED):
            # 尝试重连
            if self._auto_reconnect:
                if not self._establish_connection():
                    raise BoofuzzTargetConnectionFailedError("连接已断开，重连失败")
            else:
                raise BoofuzzTargetConnectionFailedError("连接未就绪")
        
        try:
            if self._use_bridge:
                self._call_bridge("construct_and_send", {
                    "layer": "WRAP_FUZZ",
                    "fuzz_layer": self._fuzz_layer.name,
                    "payload": hexlify(data).decode('ascii'),
                    "access_address": self._access_address
                })
            else:
                pkt = self._wrap_fuzz_data(data)
                if self._encryption_enabled:
                    self.send_encrypted(pkt)
                else:
                    self._driver.send(pkt)
            
            return len(data)
            
        except Exception as e:
            raise BoofuzzTargetConnectionFailedError(f"发送失败: {e}")
    
    def recv(self, max_bytes: int) -> bytes:
        """接收响应数据"""
        if not self._driver and not self._use_bridge:
            return b""
        
        start_time = time.time()
        while (time.time() - start_time) < self._connection_timeout:
            if len(self._recv_buffer) >= max_bytes:
                break
            if len(self._recv_buffer) > 0 and (time.time() - self._last_rx_time) > 0.1:
                # 数据接收完成
                break
            time.sleep(0.01)
        
        # 提取数据
        result = bytes(self._recv_buffer[:max_bytes])
        self._recv_buffer = self._recv_buffer[max_bytes:]
        return result
    
    @property
    def info(self) -> str:
        return (
            f"BLE Connection -> Target: {self._target_address} "
            f"Layer: {self._fuzz_layer.name} "
            f"State: {self._state.name}"
        )
    
    # ==================== 连接建立流程 ====================
    
    def _establish_connection(self) -> bool:
        """
        建立 BLE 连接 (参考 Sweyntooth 脚本模式)
        流程: SCAN → CONNECT → VERSION_IND → FEATURE_REQ → LENGTH_REQ → [MTU_REQ]
        """
        self._state = BLEConnectionState.SCANNING
        self._reset_protocol_state()
        
        # 发送扫描请求
        if self._use_bridge:
            self._call_bridge("construct_and_send", {
                "layer": "SCAN_REQ",
                "master_address": self._master_address,
                "target_address": self._target_address,
                "slave_addr_type": self._slave_addr_type
            })
        else:
            scan_req = BTLE() / BTLE_ADV(RxAdd=self._slave_addr_type) / BTLE_SCAN_REQ(
                ScanA=self._master_address,
                AdvA=self._target_address
            )
            self._driver.send(scan_req)
        
        # 等待连接建立
        start_time = time.time()
        while (time.time() - start_time) < self._connection_timeout:
            if self._state == BLEConnectionState.READY:
                return True
            if self._state == BLEConnectionState.ERROR:
                return False
            time.sleep(0.01)
        
        return False
    
    def _reset_protocol_state(self):
        """重置协议状态"""
        self._version_received = False
        self._features_received = False
        self._length_received = False
        self._mtu_exchanged = False
        self._encryption_enabled = False
        self._recv_buffer.clear()
    
    # ==================== 后台接收与协议处理 ====================
    
    def _receive_loop(self):
        """后台接收线程 - 处理所有 BLE 包"""
        while not self._stop_event.is_set():
            try:
                if self._use_bridge:
                    res_json = self._call_bridge("recv", {"timeout": 0.1})
                    data = None
                    if res_json.get("status") == "success":
                        data = unhexlify(res_json["data"])
                else:
                    data = self._driver.raw_receive()

                if data:
                    self._last_rx_time = time.time()
                    self._process_packet(data)
                else:
                    time.sleep(0.001)
            except Exception as e:
                if not self._stop_event.is_set():
                    print(f"[BLE] 接收错误: {e}")
    
    def _process_packet(self, data: bytes):
        """
        处理接收到的 BLE 包 (核心状态机)
        参考 Sweyntooth 的事件驱动处理模式
        """
        try:
            if self._use_bridge:
                # 在桥接模式下，我们需要一种方式来判断包类型，而无需本地 Scapy
                # 为简化，我们可以将数据包解析也交给桥接服务，或者在这里进行简单的字节匹配
                # 这里我们假设桥接模式下仍然使用本地 Scapy 层的定义（如果可能），
                # 或者我们需要进一步扩展桥接服务来返回解析后的包信息。
                # 目前由于 Scapy 层定义是 Python 2.7 的，Python 3 可能无法直接使用。
                # 暂时保留此处的解析逻辑，但需注意兼容性。
                from ..utils.sweyntooth.libs.scapy.layers.bluetooth4LE import BTLE
                pkt = BTLE(data)
            else:
                pkt = BTLE(data)
        except:
            return
        
        # ========== 广告阶段 ==========
        if self._state == BLEConnectionState.SCANNING:
            if (BTLE_SCAN_RSP in pkt or BTLE_ADV_IND in pkt):
                if hasattr(pkt, 'AdvA') and pkt.AdvA == self._target_address:
                    self._slave_addr_type = pkt.TxAdd
                    self._send_connection_request()
                    self._state = BLEConnectionState.CONNECTING
        
        # ========== 连接建立阶段 ==========
        elif self._state == BLEConnectionState.CONNECTING:
            if BTLE_DATA in pkt:
                self._state = BLEConnectionState.CONNECTED
                # 发送 VERSION_IND
                self._send_version_ind()
        
        # ========== 特性交换阶段 ==========
        elif self._state == BLEConnectionState.CONNECTED:
            self._handle_connected_state(pkt)
        
        elif self._state == BLEConnectionState.FEATURE_EXCHANGED:
            self._handle_feature_exchanged_state(pkt)
        
        # ========== 就绪状态 - 收集 Fuzz 响应 ==========
        elif self._state in (BLEConnectionState.READY, BLEConnectionState.ENCRYPTED):
            self._handle_ready_state(pkt)
        
        # ========== 配对状态 - 处理 SMP 包 ==========
        elif self._state == BLEConnectionState.PAIRING:
            self._handle_pairing_state(pkt)
    
    def _handle_pairing_state(self, pkt):
        """处理 PAIRING 状态的包"""
        # 检测断开
        if LL_TERMINATE_IND in pkt or LL_REJECT_IND in pkt:
            self._state = BLEConnectionState.DISCONNECTED
            self._pairing_procedure = False
            return
        
        # 处理加密启动流程
        if LL_ENC_RSP in pkt or LL_START_ENC_RSP in pkt:
            self._handle_encryption_start(pkt)
            return
        
        # 处理 SMP 包
        if SM_Hdr in pkt:
            self._handle_smp_packet(pkt)
            return
        
        # L2CAP 分片重组
        pkt = self._defragment_l2cap(pkt)
        if pkt and SM_Hdr in pkt:
            self._handle_smp_packet(pkt)
    
    def _handle_connected_state(self, pkt):
        """处理 CONNECTED 状态的包"""
        if LL_VERSION_IND in pkt:
            self._version_received = True
            self._send_feature_req()
        
        elif LL_FEATURE_RSP in pkt:
            self._features_received = True
            self._send_length_req()
            self._state = BLEConnectionState.FEATURE_EXCHANGED
        
        # 响应对方的请求
        elif LL_FEATURE_REQ in pkt:
            self._send_feature_rsp()
        
        elif LL_LENGTH_REQ in pkt:
            self._send_length_rsp()
    
    def _handle_feature_exchanged_state(self, pkt):
        """处理 FEATURE_EXCHANGED 状态的包"""
        if LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
            self._length_received = True
            
            # 如果 Fuzz ATT 层，先交换 MTU
            if self._fuzz_layer == BLEFuzzLayer.ATT:
                self._send_mtu_request()
            else:
                self._state = BLEConnectionState.READY
        
        elif ATT_Exchange_MTU_Response in pkt:
            self._mtu_exchanged = True
            self._state = BLEConnectionState.READY
        
        elif LL_LENGTH_REQ in pkt:
            self._send_length_rsp()
    
    def _handle_ready_state(self, pkt):
        """处理 READY/ENCRYPTED 状态的包 - 收集 Fuzz 响应"""
        # 检测断开
        if LL_TERMINATE_IND in pkt or LL_REJECT_IND in pkt:
            self._state = BLEConnectionState.DISCONNECTED
            return
        
        # 响应协议维护请求
        if LL_LENGTH_REQ in pkt:
            self._send_length_rsp()
            return
        
        if LL_FEATURE_REQ in pkt:
            self._send_feature_rsp()
            return
        
        # 处理 Security Request (设备请求配对)
        if SM_Security_Request in pkt:
            print(f"[BLE] 设备请求安全连接: auth={hex(pkt[SM_Security_Request].authentication)}")
            if self._enable_encryption:
                self.start_pairing()
            return
        
        # 如果已加密，先解密
        if self._encryption_enabled:
            pkt = self._receive_encrypted(pkt)
            if pkt is None:
                return
        
        # L2CAP 分片重组
        pkt = self._defragment_l2cap(pkt)
        if pkt is None:
            return
        
        # 收集有效负载数据
        if BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
            try:
                payload = self._extract_payload(pkt)
                if payload:
                    self._recv_buffer.extend(payload)
            except:
                pass
    
    def _extract_payload(self, pkt) -> bytes:
        """从 BLE 包中提取有效负载"""
        if L2CAP_Hdr in pkt:
            if ATT_Hdr in pkt:
                return raw(pkt[ATT_Hdr])
            elif SM_Hdr in pkt:
                return raw(pkt[SM_Hdr])
            else:
                return raw(pkt[L2CAP_Hdr].payload)
        elif BTLE_DATA in pkt:
            return raw(pkt[BTLE_DATA].payload)
        return b""
    
    # ==================== 协议包发送方法 ====================
    
    def _send_connection_request(self):
        """发送 CONNECT_REQ"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {
                "layer": "CONN_REQ",
                "master_address": self._master_address,
                "target_address": self._target_address,
                "slave_addr_type": self._slave_addr_type,
                "access_address": self._access_address
            })
        else:
            conn_req = BTLE() / BTLE_ADV(RxAdd=self._slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=self._master_address, AdvA=self._target_address, AA=self._access_address,
                crc_init=0x179a9c, win_size=2, win_offset=1, interval=16,
                latency=0, timeout=50, chM=0x1FFFFFFFFF, hop=5, SCA=0
            )
            self._driver.send(conn_req)
    
    def _send_version_ind(self):
        """发送 LL_VERSION_IND"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {"layer": "LL_VERSION_IND", "access_address": self._access_address})
        else:
            pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
            self._driver.send(pkt)
    
    def _send_feature_req(self):
        """发送 LL_FEATURE_REQ"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {"layer": "LL_FEATURE_REQ", "access_address": self._access_address})
        else:
            pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
                feature_set='le_encryption+le_data_len_ext'
            )
            self._driver.send(pkt)
    
    def _send_feature_rsp(self):
        """发送 LL_FEATURE_RSP"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {"layer": "LL_FEATURE_RSP", "access_address": self._access_address})
        else:
            pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
                feature_set='le_encryption+le_data_len_ext'
            )
            self._driver.send(pkt)
    
    def _send_length_req(self):
        """发送 LL_LENGTH_REQ"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {"layer": "LL_LENGTH_REQ", "access_address": self._access_address})
        else:
            pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                max_tx_bytes=251, max_rx_bytes=251
            )
            self._driver.send(pkt)
    
    def _send_length_rsp(self):
        """发送 LL_LENGTH_RSP"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {"layer": "LL_LENGTH_RSP", "access_address": self._access_address})
        else:
            pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                max_tx_bytes=251, max_rx_bytes=251
            )
            self._driver.send(pkt)
    
    def _send_mtu_request(self):
        """发送 ATT MTU 交换请求"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {"layer": "ATT_MTU_REQ", "access_address": self._access_address})
        else:
            pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
            self._driver.send(pkt)
    
    def _send_terminate(self):
        """发送断开连接请求"""
        if self._use_bridge:
            self._call_bridge("construct_and_send", {"layer": "TERMINATE", "access_address": self._access_address})
        else:
            pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND()
            self._driver.send(pkt)
    
    # ==================== Fuzz 数据包装 ====================
    
    def _wrap_fuzz_data(self, data: bytes) -> BTLE:
        """
        根据 fuzz_layer 将原始数据包装为对应协议层的 BLE 包
        这是 Boofuzz 变异数据注入的核心接口
        """
        if self._fuzz_layer == BLEFuzzLayer.RAW:
            # 完全原始模式 - 直接发送字节
            return BTLE(access_addr=self._access_address) / BTLE_DATA() / data
        
        elif self._fuzz_layer == BLEFuzzLayer.LINK_LAYER:
            # Link Layer 控制包
            return BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / data
        
        elif self._fuzz_layer == BLEFuzzLayer.L2CAP:
            # L2CAP 层
            return BTLE(access_addr=self._access_address) / BTLE_DATA() / L2CAP_Hdr() / data
        
        elif self._fuzz_layer == BLEFuzzLayer.ATT:
            # ATT/GATT 层
            return BTLE(access_addr=self._access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / data
        
        elif self._fuzz_layer == BLEFuzzLayer.SMP:
            # SMP 层
            return BTLE(access_addr=self._access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / data
        
        else:
            return BTLE(access_addr=self._access_address) / BTLE_DATA() / data
    
    # ==================== SMP/加密支持 (BLESMPServer 集成) ====================
    
    def _init_smp_server(self):
        """初始化 BLESMPServer"""
        if not HAS_SMP_SERVER:
            print("[BLE] BLESMPServer 未安装，无法启用加密")
            return False
        
        if self._smp_initialized:
            return True
        
        try:
            # 配置 SMP 服务器
            BLESMPServer.configure_connection(
                self._master_address,
                self._target_address,
                self._slave_addr_type,
                self._smp_config.io_capability,
                self._smp_config.auth_request
            )
            BLESMPServer.set_local_key_distribution(self._smp_config.initiator_key_dist)
            BLESMPServer.set_iocap(self._smp_config.io_capability)
            if self._smp_config.pin_code:
                BLESMPServer.set_pin_code(self._smp_config.pin_code)
            
            self._smp_initialized = True
            print(f"[BLE] SMP 服务器初始化完成 - IOCap: {hex(self._smp_config.io_capability)}, AuthReq: {hex(self._smp_config.auth_request)}")
            return True
        except Exception as e:
            print(f"[BLE] SMP 服务器初始化失败: {e}")
            return False
    
    def _bt_crypto_e(self, key: bytes, plaintext: bytes) -> bytes:
        """BLE 标准 AES-128 ECB 加密 (e 函数)"""
        if not HAS_CRYPTO:
            raise RuntimeError("PyCryptodome 未安装")
        aes = AES.new(bytes(key), AES.MODE_ECB)
        return aes.encrypt(bytes(plaintext))
    
    def _derive_session_key(self, skd: bytes, ltk: bytes) -> bytes:
        """
        推导会话密钥 (Session Key)
        SK = e(LTK, SKD)
        """
        return self._bt_crypto_e(ltk, skd)
    
    def send_encrypted(self, pkt):
        """
        发送加密数据
        参考 Sweyntooth non_compliance_dhcheck_skip.py 的实现
        """
        if not HAS_CRYPTO:
            print("[BLE] 加密库未安装，无法发送加密数据")
            return
        
        if not self._encryption_enabled or not self._conn_session_key:
            # 未加密，直接发送
            if self._use_bridge:
                self._call_bridge("send", {"data": hexlify(raw(pkt)).decode('ascii')})
            else:
                self._driver.send(pkt)
            return
        
        raw_pkt = bytearray(raw(pkt))
        aa = raw_pkt[:4]        # Access Address
        header = raw_pkt[4]     # BLE header
        length = raw_pkt[5] + 4 # +4 bytes for MIC
        crc = b'\x00\x00\x00'   # Dummy CRC (Dongle 自动计算)
        
        # 构建 Nonce: packet_counter (5 bytes) + IV (8 bytes)
        pkt_count = bytearray(struct.pack("<Q", self._conn_tx_packet_counter)[:5])
        pkt_count[4] |= 0x80  # 设置方向位: Master -> Slave
        nonce = bytes(pkt_count) + self._conn_iv
        
        # AES-CCM 加密
        aes = AES.new(self._conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        # AAD: header 清除 NESN, SN, MD 位
        aes.update(bytes([header & 0xE3]))
        
        # 加密 payload (排除 CRC)
        enc_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3])
        
        self._conn_tx_packet_counter += 1
        
        # 组装加密包
        encrypted_data = bytes(aa) + bytes([header]) + bytes([length]) + enc_pkt + mic + crc
        if self._use_bridge:
            self._call_bridge("send", {"data": hexlify(encrypted_data).decode('ascii')})
        else:
            self._driver.raw_send(encrypted_data)
        print(f"[BLE] TX ---> [Encrypted] {pkt.summary()[7:] if hasattr(pkt, 'summary') else hexlify(bytes(raw_pkt[6:-3])).decode()}")
    
    def _receive_encrypted(self, pkt) -> Optional[BTLE]:
        """
        接收并解密数据
        参考 Sweyntooth 的 receive_encrypted 实现
        """
        if not HAS_CRYPTO:
            return pkt
        
        if not self._encryption_enabled or not self._conn_session_key:
            return pkt
        
        raw_pkt = bytearray(raw(pkt))
        aa = raw_pkt[:4]
        header = raw_pkt[4]
        length = raw_pkt[5]
        
        # 忽略空 PDU
        if length == 0 or length < 5:
            return pkt
        
        # 减去 4 字节 MIC
        length -= 4
        
        # 构建 Nonce
        pkt_count = bytearray(struct.pack("<Q", self._conn_rx_packet_counter)[:5])
        pkt_count[4] &= 0x7F  # 清除方向位: Slave -> Master
        nonce = bytes(pkt_count) + self._conn_iv
        
        # AES-CCM 解密
        aes = AES.new(self._conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        aes.update(bytes([header & 0xE3]))
        
        # 解密 payload
        dec_pkt = aes.decrypt(raw_pkt[6:-4-3])  # 排除 MIC 和 CRC
        
        self._conn_rx_packet_counter += 1
        
        try:
            # 验证 MIC
            mic = raw_pkt[6 + length: -3]
            aes.verify(mic)
            # 重建明文包
            return BTLE(bytes(aa) + bytes([header]) + bytes([length]) + dec_pkt + b'\x00\x00\x00')
        except Exception as e:
            print(f"[BLE] MIC 验证失败: {e}")
            return None
    
    def _defragment_l2cap(self, pkt):
        """
        L2CAP 分片重组
        参考 Sweyntooth 的 defragment_l2cap 实现
        """
        if L2CAP_Hdr in pkt and pkt[L2CAP_Hdr].len + 4 > pkt[BTLE_DATA].len:
            # 分片开始
            self._fragment_start = True
            self._fragment_left = pkt[L2CAP_Hdr].len
            self._fragment_buffer = raw(pkt)[:-3]  # 排除 CRC
            return None
        elif self._fragment_start and BTLE_DATA in pkt and pkt[BTLE_DATA].LLID == 0x01:
            # 继续分片
            self._fragment_left -= pkt[BTLE_DATA].len + 4
            self._fragment_buffer += raw(pkt[BTLE_DATA].payload)
            if pkt[BTLE_DATA].len >= self._fragment_left:
                # 分片完成
                self._fragment_start = False
                pkt = BTLE(self._fragment_buffer + b'\x00\x00\x00')
                pkt.len = len(pkt[BTLE_DATA].payload)
                return pkt
            return None
        else:
            self._fragment_start = False
            return pkt
    
    # ==================== SMP 配对流程 ====================
    
    def start_pairing(self) -> bool:
        """
        启动 SMP 配对流程
        返回: 是否成功启动配对
        """
        if not HAS_SMP_SERVER:
            print("[BLE] BLESMPServer 未安装，无法配对")
            return False
        
        if self._state not in (BLEConnectionState.READY, BLEConnectionState.FEATURE_EXCHANGED):
            print(f"[BLE] 当前状态 {self._state.name} 无法启动配对")
            return False
        
        # 初始化 SMP 服务器
        if not self._init_smp_server():
            return False
        
        # 进入配对状态
        self._state = BLEConnectionState.PAIRING
        self._pairing_procedure = True
        
        # 发送 Pairing Request
        pairing_req_data = BLESMPServer.pairing_request()
        pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(pairing_req_data)
        if self._use_bridge:
            self._call_bridge("send", {"data": hexlify(raw(pkt)).decode('ascii')})
        else:
            self._driver.send(pkt)
        print("[BLE] 发送 Pairing Request")
        
        return True
    
    def _handle_smp_packet(self, pkt):
        """
        处理 SMP 协议包
        通过 BLESMPServer 进行状态机处理
        """
        if not HAS_SMP_SERVER or not self._pairing_procedure:
            return
        
        if SM_Hdr not in pkt:
            return
        
        # 提取 L2CAP payload 并转换为 HCI 格式给 BLESMPServer
        smp_data = raw(pkt[SM_Hdr:])
        
        # 构建 HCI ACL 数据包
        hci_data = HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr(cid=6) / smp_data  # CID 6 = SMP
        
        # 发送给 BLESMPServer 并获取响应
        response = BLESMPServer.send_hci(raw(hci_data))
        
        if response:
            # BLESMPServer 返回了响应数据，发送给设备
            resp_pkt = HCI_Hdr(response)
            if HCI_ACL_Hdr in resp_pkt:
                # 提取 L2CAP payload
                l2cap_data = raw(resp_pkt[L2CAP_Hdr:])
                ble_pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / L2CAP_Hdr() / l2cap_data
                if self._use_bridge:
                    self._call_bridge("send", {"data": hexlify(raw(ble_pkt)).decode('ascii')})
                else:
                    self._driver.send(ble_pkt)
                print(f"[BLE] SMP 响应已发送")
        
        # 检查配对状态
        if SM_Pairing_Response in pkt:
            print("[BLE] 收到 Pairing Response")
        elif SM_Public_Key in pkt:
            print("[BLE] 收到 Public Key")
        elif SM_Confirm in pkt:
            print("[BLE] 收到 Confirm")
        elif SM_Random in pkt:
            print("[BLE] 收到 Random")
        elif SM_Failed in pkt:
            print(f"[BLE] 配对失败: {pkt[SM_Failed].reason}")
            self._pairing_procedure = False
            self._state = BLEConnectionState.READY
    
    def _handle_encryption_start(self, pkt):
        """处理加密启动流程"""
        if LL_ENC_RSP in pkt:
            # 收到加密响应，提取 SKD 和 IV
            self._conn_skd = pkt[LL_ENC_RSP].skds + self._conn_skd[:8]  # SKDm + SKDs
            self._conn_iv = pkt[LL_ENC_RSP].ivs + self._conn_iv[:4]     # IVm + IVs
            
            # 获取 LTK
            if HAS_SMP_SERVER:
                self._conn_ltk = BLESMPServer.get_ltk()
            
            if self._conn_ltk:
                # 推导会话密钥
                self._conn_session_key = self._derive_session_key(self._conn_skd, self._conn_ltk)
                print(f"[BLE] 会话密钥已生成")
        
        elif LL_START_ENC_RSP in pkt:
            # 加密已启动
            self._encryption_enabled = True
            self._conn_tx_packet_counter = 0
            self._conn_rx_packet_counter = 0
            self._pairing_procedure = False
            self._state = BLEConnectionState.ENCRYPTED
            print("[BLE] 加密已启用")
            
            if self._on_pairing_complete:
                self._on_pairing_complete()
    
    def _send_enc_request(self):
        """
        发送 LL_ENC_REQ 启动加密
        """
        import os
        # 生成随机 SKD 和 IV
        skdm = os.urandom(8)
        ivm = os.urandom(4)
        rand = os.urandom(8)
        ediv = 0
        
        self._conn_skd = skdm  # Master 部分
        self._conn_iv = ivm    # Master 部分
        
        pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(
            rand=rand, ediv=ediv, skdm=skdm, ivm=ivm
        )
        if self._use_bridge:
            self._call_bridge("send", {"data": hexlify(raw(pkt)).decode('ascii')})
        else:
            self._driver.send(pkt)
        print("[BLE] 发送 LL_ENC_REQ")
    
    def _send_start_enc_req(self):
        """发送 LL_START_ENC_REQ"""
        pkt = BTLE(access_addr=self._access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_REQ()
        if self._use_bridge:
            self._call_bridge("send", {"data": hexlify(raw(pkt)).decode('ascii')})
        else:
            self._driver.send(pkt)
        print("[BLE] 发送 LL_START_ENC_REQ")
    
    # ==================== 公共接口 ====================
    
    def set_crash_callback(self, callback: Callable):
        """设置崩溃检测回调"""
        self._on_crash_detected = callback
    
    def set_pairing_complete_callback(self, callback: Callable):
        """设置配对完成回调"""
        self._on_pairing_complete = callback
    
    def is_encrypted(self) -> bool:
        """检查连接是否已加密"""
        return self._encryption_enabled
    
    def is_target_alive(self) -> bool:
        """检测目标设备是否存活"""
        if self._state in (BLEConnectionState.DISCONNECTED, BLEConnectionState.ERROR):
            return False
        return (time.time() - self._last_rx_time) < self._crash_timeout
    
    def get_state(self) -> BLEConnectionState:
        """获取当前连接状态"""
        return self._state
    
    def get_smp_config(self) -> SMPConfig:
        """获取 SMP 配置"""
        return self._smp_config
    
    def reconnect(self) -> bool:
        """手动重连"""
        self.close()
        time.sleep(0.5)
        try:
            self.open()
            return True
        except:
            return False
