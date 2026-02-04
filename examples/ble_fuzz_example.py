#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
BLE Fuzzing 示例 - 基于 Boofuzz + Sweyntooth

本示例展示如何使用重构后的 BLEConnection 对不同 BLE 协议层进行 Fuzzing。

支持的 Fuzz 层:
- LINK_LAYER: Link Layer 控制包 (LL_VERSION_IND, LL_FEATURE_REQ 等)
- L2CAP: L2CAP 层
- ATT: ATT/GATT 层 (最常用)
- SMP: Security Manager Protocol
- RAW: 原始字节

使用前请确保:
1. NRF52 Dongle 已连接并刷入 Sweyntooth 固件
2. 目标 BLE 设备处于可连接广告状态
3. 修改 TARGET_ADDRESS 为目标设备的 MAC 地址
4. **启动 Socket 桥接服务** (Python 2.7): `python boofuzz/utils/sweyntooth/socket_bridge.py`

加密功能需要 (在 Python 2.7 桥接端):
- 安装 BLESMPServer: cd boofuzz/utils/sweyntooth/libs/smp_server && python setup.py install
- 安装 PyCryptodome: pip install pycryptodome
"""

from boofuzz import *
from boofuzz.connections.ble_connection import (
    BLEConnection,
    BLEFuzzLayer,
    BLEConnectionState,
    SMPConfig,
    BLEIOCapability,
    BLEAuthReq
)

# ==================== 配置参数 ====================

# NRF52 Dongle 串口 (Windows: COM3, Linux: /dev/ttyACM0)
SERIAL_PORT = 'COM3'

# 目标 BLE 设备 MAC 地址
TARGET_ADDRESS = '80:ea:ca:80:00:01'


# ==================== 示例 1: ATT/GATT 层 Fuzzing ====================

def fuzz_att_layer():
    """
    对 ATT/GATT 层进行 Fuzzing
    这是最常见的 BLE Fuzzing 场景，用于测试 GATT 服务的健壮性
    """
    print("=" * 60)
    print("ATT/GATT 层 Fuzzing")
    print("=" * 60)
    
    # 创建 BLE 连接 (ATT 层)
    connection = BLEConnection(
        port=SERIAL_PORT,
        target_address=TARGET_ADDRESS,
        fuzz_layer=BLEFuzzLayer.ATT,  # 指定 Fuzz ATT 层
        auto_reconnect=True,
        bridge_host='127.0.0.1',
        bridge_port=5000
    )
    
    target = Target(connection=connection)
    session = Session(
        target=target,
        sleep_time=0.1,
        restart_sleep_time=1.0
    )
    
    # ----- 定义 ATT 协议结构 -----
    
    # GATT Read Request
    s_initialize("ATT_Read_Request")
    s_byte(0x0A, name="Opcode", fuzzable=False)  # ATT_READ_REQ
    s_word(0x0001, name="Handle", endian=LITTLE_ENDIAN)  # Attribute Handle
    
    # GATT Write Request
    s_initialize("ATT_Write_Request")
    s_byte(0x12, name="Opcode", fuzzable=False)  # ATT_WRITE_REQ
    s_word(0x0012, name="Handle", endian=LITTLE_ENDIAN)
    s_string("FuzzPayload", name="Value", max_len=512)
    
    # GATT Write Command (无响应)
    s_initialize("ATT_Write_Command")
    s_byte(0x52, name="Opcode", fuzzable=False)  # ATT_WRITE_CMD
    s_word(0x0012, name="Handle", endian=LITTLE_ENDIAN)
    s_random(name="RandomValue", min_length=1, max_length=247)
    
    # ATT Find Information Request
    s_initialize("ATT_Find_Info_Request")
    s_byte(0x04, name="Opcode", fuzzable=False)  # ATT_FIND_INFO_REQ
    s_word(0x0001, name="StartHandle", endian=LITTLE_ENDIAN)
    s_word(0xFFFF, name="EndHandle", endian=LITTLE_ENDIAN)
    
    # ATT Read By Group Type Request
    s_initialize("ATT_Read_By_Group_Type")
    s_byte(0x10, name="Opcode", fuzzable=False)  # ATT_READ_BY_GROUP_TYPE_REQ
    s_word(0x0001, name="StartHandle", endian=LITTLE_ENDIAN)
    s_word(0xFFFF, name="EndHandle", endian=LITTLE_ENDIAN)
    s_word(0x2800, name="UUID", endian=LITTLE_ENDIAN)  # Primary Service UUID
    
    # 构建 Fuzz 图
    session.connect(s_get("ATT_Read_Request"))
    session.connect(s_get("ATT_Write_Request"))
    session.connect(s_get("ATT_Write_Command"))
    session.connect(s_get("ATT_Find_Info_Request"))
    session.connect(s_get("ATT_Read_By_Group_Type"))
    
    # 开始 Fuzzing
    session.fuzz()


# ==================== 示例 2: Link Layer Fuzzing ====================

def fuzz_link_layer():
    """
    对 Link Layer 进行 Fuzzing
    用于测试 BLE 控制器的链路层实现
    """
    print("=" * 60)
    print("Link Layer Fuzzing")
    print("=" * 60)
    
    connection = BLEConnection(
        port=SERIAL_PORT,
        target_address=TARGET_ADDRESS,
        fuzz_layer=BLEFuzzLayer.LINK_LAYER,
        auto_reconnect=True,
        bridge_host='127.0.0.1',
        bridge_port=5000
    )
    
    target = Target(connection=connection)
    session = Session(target=target, sleep_time=0.1)
    
    # ----- 定义 Link Layer 控制包结构 -----
    
    # LL_VERSION_IND (参考 Sweyntooth)
    s_initialize("LL_VERSION_IND")
    s_byte(0x0C, name="LL_Opcode", fuzzable=False)  # VERSION_IND opcode
    s_byte(0x09, name="VersNr")  # BLE Version (0x09 = 5.0)
    s_word(0x0059, name="CompId", endian=LITTLE_ENDIAN)  # Company ID
    s_word(0x0001, name="SubVersNr", endian=LITTLE_ENDIAN)  # Subversion
    
    # LL_FEATURE_REQ
    s_initialize("LL_FEATURE_REQ")
    s_byte(0x08, name="LL_Opcode", fuzzable=False)  # FEATURE_REQ opcode
    s_qword(0x000000001F, name="FeatureSet", endian=LITTLE_ENDIAN)
    
    # LL_LENGTH_REQ (潜在溢出点)
    s_initialize("LL_LENGTH_REQ")
    s_byte(0x14, name="LL_Opcode", fuzzable=False)  # LENGTH_REQ opcode
    s_word(0x00FB, name="MaxRxOctets", endian=LITTLE_ENDIAN)  # 可尝试大值
    s_word(0x0148, name="MaxRxTime", endian=LITTLE_ENDIAN)
    s_word(0x00FB, name="MaxTxOctets", endian=LITTLE_ENDIAN)
    s_word(0x0148, name="MaxTxTime", endian=LITTLE_ENDIAN)
    
    # LL_ENC_REQ (加密请求 - 敏感)
    s_initialize("LL_ENC_REQ")
    s_byte(0x03, name="LL_Opcode", fuzzable=False)  # ENC_REQ opcode
    s_random(name="Rand", min_length=8, max_length=8)
    s_word(0x0000, name="EDIV", endian=LITTLE_ENDIAN)
    s_random(name="SKDm", min_length=8, max_length=8)
    s_random(name="IVm", min_length=4, max_length=4)
    
    session.connect(s_get("LL_VERSION_IND"))
    session.connect(s_get("LL_FEATURE_REQ"))
    session.connect(s_get("LL_LENGTH_REQ"))
    session.connect(s_get("LL_ENC_REQ"))
    
    session.fuzz()


# ==================== 示例 3: SMP Fuzzing ====================

def fuzz_smp_layer():
    """
    对 SMP (Security Manager Protocol) 进行 Fuzzing
    用于测试 BLE 配对/加密实现的安全性
    """
    print("=" * 60)
    print("SMP 层 Fuzzing")
    print("=" * 60)
    
    connection = BLEConnection(
        port=SERIAL_PORT,
        target_address=TARGET_ADDRESS,
        fuzz_layer=BLEFuzzLayer.SMP,
        auto_reconnect=True,
        bridge_host='127.0.0.1',
        bridge_port=5000
    )
    
    target = Target(connection=connection)
    session = Session(target=target, sleep_time=0.2)
    
    # ----- 定义 SMP 协议结构 -----
    
    # SM_Pairing_Request (参考 Sweyntooth key_size_overflow)
    s_initialize("SM_Pairing_Request")
    s_byte(0x01, name="Code", fuzzable=False)  # Pairing Request
    s_byte(0x04, name="IOCapability")  # KeyboardDisplay
    s_byte(0x00, name="OOBDataFlag")
    s_byte(0x05, name="AuthReq")  # Bonding + MITM
    s_byte(0x10, name="MaxEncKeySize")  # 可尝试 0x00 或 0xFF
    s_byte(0x07, name="InitiatorKeyDist")
    s_byte(0x07, name="ResponderKeyDist")
    
    # SM_Public_Key (LE Secure Connections)
    s_initialize("SM_Public_Key")
    s_byte(0x0C, name="Code", fuzzable=False)  # Public Key
    s_random(name="PublicKeyX", min_length=32, max_length=32)
    s_random(name="PublicKeyY", min_length=32, max_length=32)
    
    # SM_Pairing_Confirm
    s_initialize("SM_Pairing_Confirm")
    s_byte(0x03, name="Code", fuzzable=False)  # Pairing Confirm
    s_random(name="ConfirmValue", min_length=16, max_length=16)
    
    # SM_Pairing_Random
    s_initialize("SM_Pairing_Random")
    s_byte(0x04, name="Code", fuzzable=False)  # Pairing Random
    s_random(name="RandomValue", min_length=16, max_length=16)
    
    # SM_DHKey_Check
    s_initialize("SM_DHKey_Check")
    s_byte(0x0D, name="Code", fuzzable=False)  # DHKey Check
    s_random(name="DHKeyCheck", min_length=16, max_length=16)
    
    session.connect(s_get("SM_Pairing_Request"))
    session.connect(s_get("SM_Pairing_Request"), s_get("SM_Public_Key"))
    session.connect(s_get("SM_Public_Key"), s_get("SM_Pairing_Confirm"))
    session.connect(s_get("SM_Pairing_Confirm"), s_get("SM_Pairing_Random"))
    session.connect(s_get("SM_Pairing_Random"), s_get("SM_DHKey_Check"))
    
    session.fuzz()


# ==================== 示例 4: L2CAP Fuzzing ====================

def fuzz_l2cap_layer():
    """
    对 L2CAP 层进行 Fuzzing
    用于测试 L2CAP 分片、信令等功能
    """
    print("=" * 60)
    print("L2CAP 层 Fuzzing")
    print("=" * 60)
    
    connection = BLEConnection(
        port=SERIAL_PORT,
        target_address=TARGET_ADDRESS,
        fuzz_layer=BLEFuzzLayer.L2CAP,
        auto_reconnect=True,
        bridge_host='127.0.0.1',
        bridge_port=5000
    )
    
    target = Target(connection=connection)
    session = Session(target=target, sleep_time=0.1)
    
    # ----- 定义 L2CAP 协议结构 -----
    
    # L2CAP 连接参数更新请求
    s_initialize("L2CAP_Connection_Parameter_Update_Req")
    s_byte(0x12, name="Code", fuzzable=False)  # Connection Parameter Update Request
    s_byte(0x01, name="Identifier")
    s_word(0x0008, name="Length", endian=LITTLE_ENDIAN)
    s_word(0x0006, name="IntervalMin", endian=LITTLE_ENDIAN)
    s_word(0x0C80, name="IntervalMax", endian=LITTLE_ENDIAN)
    s_word(0x0000, name="SlaveLatency", endian=LITTLE_ENDIAN)
    s_word(0x00C8, name="TimeoutMultiplier", endian=LITTLE_ENDIAN)
    
    # L2CAP 畸形分片 (参考 Sweyntooth invalid_lcap_fragment)
    s_initialize("L2CAP_Malformed_Fragment")
    s_random(name="MalformedPayload", min_length=1, max_length=247)
    
    session.connect(s_get("L2CAP_Connection_Parameter_Update_Req"))
    session.connect(s_get("L2CAP_Malformed_Fragment"))
    
    session.fuzz()


# ==================== 示例 5: 自定义回调 ====================

def fuzz_with_callbacks():
    """
    使用回调函数监控 Fuzz 过程
    """
    print("=" * 60)
    print("带回调的 Fuzzing")
    print("=" * 60)
    
    connection = BLEConnection(
        port=SERIAL_PORT,
        target_address=TARGET_ADDRESS,
        fuzz_layer=BLEFuzzLayer.ATT,
        crash_timeout=5.0
    )
    
    def pre_send_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
        """发送前回调"""
        print(f"[*] 即将发送 Fuzz 数据...")
    
    def post_test_case_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
        """测试用例完成后回调"""
        # 检查目标是否存活
        if hasattr(sock, 'is_target_alive') and not sock.is_target_alive():
            print("[!] 目标可能已崩溃!")
            fuzz_data_logger.log_info("Target may have crashed")
    
    target = Target(connection=connection)
    session = Session(
        target=target,
        pre_send_callbacks=[pre_send_callback],
        post_test_case_callbacks=[post_test_case_callback]
    )
    
    s_initialize("Simple_ATT_Write")
    s_byte(0x52, name="Opcode", fuzzable=False)
    s_word(0x0012, name="Handle", endian=LITTLE_ENDIAN)
    s_string("FUZZ", name="Value", max_len=200)
    
    session.connect(s_get("Simple_ATT_Write"))
    session.fuzz()


# ==================== 示例 6: 加密连接 Fuzzing ====================

def fuzz_encrypted_connection():
    """
    在加密连接下进行 Fuzzing
    使用 BLESMPServer 自动完成配对和加密建立
    
    适用场景:
    - 需要加密才能访问的 GATT 特征
    - 测试加密通道的健壮性
    - 测试配对后的安全机制
    """
    print("=" * 60)
    print("加密连接 Fuzzing (BLESMPServer 集成)")
    print("=" * 60)
    
    # 方法 1: 使用预定义的 SMP 配置
    # smp_config = SMPConfig.just_works()           # Just Works 配对
    # smp_config = SMPConfig.secure_connections()  # LE Secure Connections
    
    # 方法 2: 自定义 SMP 配置
    smp_config = SMPConfig(
        io_capability=BLEIOCapability.NO_INPUT_NO_OUTPUT,
        auth_request=BLEAuthReq.SECURE_CONNECTIONS,
        max_key_size=16,
        initiator_key_dist=0x07,
        responder_key_dist=0x07
    )
    
    connection = BLEConnection(
        port=SERIAL_PORT,
        target_address=TARGET_ADDRESS,
        fuzz_layer=BLEFuzzLayer.ATT,
        enable_encryption=True,     # 启用加密
        smp_config=smp_config,      # SMP 配置
        auto_reconnect=True,
        bridge_host='127.0.0.1',
        bridge_port=5000
    )
    
    # 设置配对完成回调
    def on_pairing_complete():
        print("[*] 配对完成，连接已加密!")
    
    connection.set_pairing_complete_callback(on_pairing_complete)
    
    target = Target(connection=connection)
    session = Session(
        target=target,
        sleep_time=0.2,
        restart_sleep_time=2.0  # 加密连接需要更多时间
    )
    
    # ----- 加密连接下的 ATT 操作 -----
    
    # 读取受保护特征 (需要加密)
    s_initialize("ATT_Read_Protected")
    s_byte(0x0A, name="Opcode", fuzzable=False)  # ATT_READ_REQ
    s_word(0x0010, name="Handle", endian=LITTLE_ENDIAN)  # 受保护的 Handle
    
    # 写入受保护特征
    s_initialize("ATT_Write_Protected")
    s_byte(0x12, name="Opcode", fuzzable=False)  # ATT_WRITE_REQ
    s_word(0x0010, name="Handle", endian=LITTLE_ENDIAN)
    s_string("EncryptedFuzz", name="Value", max_len=200)
    
    session.connect(s_get("ATT_Read_Protected"))
    session.connect(s_get("ATT_Write_Protected"))
    
    # 打开连接并启动配对
    print("[*] 建立连接...")
    connection.open()
    
    print("[*] 启动配对流程...")
    if connection.start_pairing():
        # 等待加密完成
        import time
        timeout = 10.0
        start = time.time()
        while (time.time() - start) < timeout:
            if connection.is_encrypted():
                print(f"[*] 加密已建立，开始 Fuzzing!")
                break
            time.sleep(0.1)
        
        if connection.is_encrypted():
            session.fuzz()
        else:
            print("[!] 配对/加密建立失败")
    else:
        print("[!] 无法启动配对")
    
    connection.close()


# ==================== 示例 7: 手动配对流程 Fuzzing ====================

def fuzz_pairing_manually():
    """
    手动控制配对流程，在各个阶段注入畸形数据
    这是一个更高级的用法，用于测试 SMP 状态机的健壮性
    """
    print("=" * 60)
    print("手动配对流程 Fuzzing")
    print("=" * 60)
    
    connection = BLEConnection(
        port=SERIAL_PORT,
        target_address=TARGET_ADDRESS,
        fuzz_layer=BLEFuzzLayer.SMP,
        enable_encryption=False,  # 我们手动控制配对
        auto_reconnect=True,
        bridge_host='127.0.0.1',
        bridge_port=5000
    )
    
    target = Target(connection=connection)
    session = Session(target=target, sleep_time=0.3)
    
    # ----- 定义配对包序列 -----
    
    # 步骤 1: Pairing Request
    s_initialize("Pairing_Request")
    s_byte(0x01, name="Code", fuzzable=False)
    s_byte(0x03, name="IOCap")  # NoInputNoOutput
    s_byte(0x00, name="OOB")
    s_byte(0x09, name="AuthReq")  # SC + Bonding
    s_byte(0x10, name="MaxKeySize")  # Fuzz this!
    s_byte(0x07, name="InitKeyDist")
    s_byte(0x07, name="RespKeyDist")
    
    # 步骤 2: Public Key (畸形输入)
    s_initialize("Fuzz_Public_Key")
    s_byte(0x0C, name="Code", fuzzable=False)
    s_bytes(b'\x00' * 32, name="PublicKeyX", max_len=64)  # 允许超长
    s_bytes(b'\x00' * 32, name="PublicKeyY", max_len=64)
    
    # 步骤 3: DHKey Check (畸形输入)
    s_initialize("Fuzz_DHKey_Check")
    s_byte(0x0D, name="Code", fuzzable=False)
    s_random(name="FuzzDHKeyCheck", min_length=1, max_length=32)  # 长度变异
    
    # 构建状态机流程
    session.connect(s_get("Pairing_Request"))
    session.connect(s_get("Pairing_Request"), s_get("Fuzz_Public_Key"))
    session.connect(s_get("Fuzz_Public_Key"), s_get("Fuzz_DHKey_Check"))
    
    session.fuzz()


# ==================== 主函数 ====================

def main():
    import sys
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║           BLE Fuzzing - Boofuzz + Sweyntooth                  ║
║                                                               ║
║  请选择要运行的 Fuzz 模式:                                     ║
║    1. ATT/GATT 层 Fuzzing (最常用)                             ║
║    2. Link Layer Fuzzing                                      ║
║    3. SMP 层 Fuzzing                                          ║
║    4. L2CAP 层 Fuzzing                                        ║
║    5. 带回调的 Fuzzing                                         ║
║    6. 加密连接 Fuzzing (BLESMPServer)   [NEW]                  ║
║    7. 手动配对流程 Fuzzing               [NEW]                  ║
║    0. 退出                                                     ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    try:
        choice = input("请输入选项 [0-7]: ").strip()
        
        if choice == '1':
            fuzz_att_layer()
        elif choice == '2':
            fuzz_link_layer()
        elif choice == '3':
            fuzz_smp_layer()
        elif choice == '4':
            fuzz_l2cap_layer()
        elif choice == '5':
            fuzz_with_callbacks()
        elif choice == '6':
            fuzz_encrypted_connection()
        elif choice == '7':
            fuzz_pairing_manually()
        elif choice == '0':
            print("退出")
            sys.exit(0)
        else:
            print("无效选项")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(0)


if __name__ == "__main__":
    main()
