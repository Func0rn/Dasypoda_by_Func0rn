from boofuzz import *
from boofuzz.connections.ble_connection import BLEConnection

def main():
    # 1. 定义 BLE 连接参数 (请根据实际硬件修改)
    # port: NRF52 Dongle 串口
    # advertiser_address: 目标 BLE 设备的 MAC 地址
    connection = BLEConnection(port='COM3', advertiser_address='80:ea:ca:80:00:01')

    # 2. 定义目标和会话
    target = Target(connection=connection)
    session = Session(target=target)

    # 3. 定义协议结构 (例如 Fuzz 一个简单的 GATT 写操作)
    s_initialize("BLE_GATT_Write")
    if s_block("GATT_Header"):
        s_byte(0x52, name="Opcode", fuzzable=False) # Write Command
        s_word(0x0012, name="Attribute_Handle", fuzzable=False)
    if s_block("GATT_Payload"):
        s_string("FuzzMe", name="Value")
    s_block_end()

    # 4. 开始 Fuzzing
    session.connect(s_get("BLE_GATT_Write"))
    session.fuzz()

if __name__ == "__main__":
    main()