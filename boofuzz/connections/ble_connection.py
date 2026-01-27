import time
from boofuzz.connections import itarget_connection
from boofuzz.exception import BoofuzzTargetConnectionFailedError
#外部sweyntooth提供的链路导入
from ..utils.sweyntooth.drivers.NRF52_dongle import NRF52Dongle
from ..utils.sweyntooth.libs.scapy.layers.bluetooth4LE import BTLE, BTLE_DATA
from ..utils.sweyntooth.libs.scapy.utils import raw

class BLEConnection(itarget_connection.ITargetConnection):
    """
    基于 Sweyntooth NRF52 Dongle 实现的 boofuzz BLE 通信通路。
    
    Args:
        port (str): NRF52 Dongle 所在的串口号 (如 'COM3' 或 '/dev/ttyACM0')。
        advertiser_address (str): 目标外设的 MAC 地址 (如 '80:ea:ca:80:00:01')。
        baudrate (int): 串口波特率，默认为 115200。
        timeout (float): 接收超时时间。
    """

    def __init__(self, port, advertiser_address, baudrate=115200, timeout=5.0):
        if NRF52Dongle is None:
            raise RuntimeError("未能加载 Sweyntooth 驱动，请检查路径配置。")
        
        self._port = port
        self._advertiser_address = advertiser_address.lower()
        self._baudrate = baudrate
        self._timeout = timeout
        self._driver = None
        
        # 内部缓冲区，用于存放驱动收到的原始数据
        self._recv_buffer = b""

    def open(self):
        """
        打开串口并初始化 Sweyntooth 驱动。
        """
        try:
            self._driver = NRF52Dongle(self._port, str(self._baudrate))
            # 这里可以根据需要添加 Sweyntooth 的连接初始化逻辑（如扫描和建立连接）
            # 由于 Sweyntooth 的脚本通常在循环中处理连接，这里仅做硬件初始化
        except Exception as e:
            raise BoofuzzTargetConnectionFailedError(f"无法初始化 NRF52 Dongle: {e}")

    def close(self):
        """
        关闭驱动连接。
        """
        if self._driver:
            self._driver.close()
            self._driver = None

    def send(self, data):
        """
        发送数据。
        boofuzz 传入的是 bytes，我们将其包装为 BTLE 数据包。
        """
        if not self._driver:
            raise BoofuzzTargetConnectionFailedError("连接未打开，无法发送数据。")

        try:
            # 将 boofuzz 的变异字节流包装为 BTLE 链路层数据包
            # 注意：这里假设发送的是数据 PDU，如果是 LL 控制包则需要不同包装
            pkt = BTLE(access_addr=0x8E89BED6) / BTLE_DATA() / data
            self._driver.send(pkt)
            return len(data)
        except Exception as e:
            raise BoofuzzTargetConnectionFailedError(f"BLE 发送失败: {e}")

    def recv(self, max_bytes):
        """
        接收数据。
        从 Sweyntooth 驱动轮询数据。
        """
        if not self._driver:
            raise BoofuzzTargetConnectionFailedError("连接未打开，无法接收数据。")

        start_time = time.time()
        received_data = b""

        while (time.time() - start_time) < self._timeout and len(received_data) < max_bytes:
            raw_pkt = self._driver.raw_receive()
            if raw_pkt:
                # 提取 BTLE 包中的有效负载数据
                try:
                    btle_pkt = BTLE(raw_pkt)
                    if btle_pkt.haslayer(BTLE_DATA):
                        payload = raw(btle_pkt[BTLE_DATA].payload)
                        received_data += payload
                except Exception:
                    # 如果解析失败，可能是非标准包，直接返回原始数据
                    received_data += raw_pkt
            else:
                time.sleep(0.01)  # 避免过度占用 CPU

        return received_data

    @property
    def info(self):
        return f"BLE Connection -> Target: {self._advertiser_address} via {self._port}"