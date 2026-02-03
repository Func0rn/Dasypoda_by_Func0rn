# -*- coding: utf-8 -*-
"""
Sweyntooth Flask Bridge (Python 2.7)
为 Python 3 的 Boofuzz 提供 BLE 连接桥接接口。
"""

import os
import sys
import time
import binascii
from flask import Flask, request, jsonify

# 注入路径以加载 sweyntooth 库
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, 'libs'))

from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import BTLE
from scapy.utils import raw

app = Flask(__name__)

# 全局驱动实例
driver = None

@app.route('/init', methods=['POST'])
def init_driver():
    global driver
    params = request.json
    port = params.get('port', 'COM1')
    baudrate = params.get('baudrate', '115200')
    
    try:
        if driver:
            driver.close()
        driver = NRF52Dongle(port, baudrate)
        return jsonify({"status": "success", "message": "Driver initialized on " + port})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/send', methods=['POST'])
def send_packet():
    global driver
    if not driver:
        return jsonify({"status": "error", "message": "Driver not initialized"}), 400
    
    params = request.json
    data_hex = params.get('data')
    if not data_hex:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    try:
        data = binascii.unhexlify(data_hex)
        # 假设发送的是原始字节，或者需要包装成 BTLE
        # 这里直接使用 driver.raw_send 或者根据需求包装
        # 为了通用性，我们这里支持发送原始字节流
        driver.raw_send(data)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/recv', methods=['GET'])
def recv_packet():
    global driver
    if not driver:
        return jsonify({"status": "error", "message": "Driver not initialized"}), 400
    
    timeout = float(request.args.get('timeout', 0.1))
    start_time = time.time()
    
    try:
        while (time.time() - start_time) < timeout:
            data = driver.raw_receive()
            if data:
                return jsonify({
                    "status": "success", 
                    "data": binascii.hexlify(data).decode('ascii')
                })
            time.sleep(0.001)
        return jsonify({"status": "timeout", "data": None})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/close', methods=['POST'])
def close_driver():
    global driver
    if driver:
        driver.close()
        driver = None
    return jsonify({"status": "success"})

if __name__ == '__main__':
    # 默认运行在 5000 端口
    app.run(host='127.0.0.1', port=5000, debug=False)