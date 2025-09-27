import math
import json
import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Base64 常量定义（来自第一个JS文件）
BASE64_ARRAY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
BASE64_ENCODE_TABLE = {i: ord(c) for i, c in enumerate(BASE64_ARRAY)}
BASE64_DECODE_TABLE = {ord(c): i for i, c in enumerate(BASE64_ARRAY)}

# AES 和 C# 头部常量（来自第二个JS文件）
C_SHARP_HEADER = bytes([0, 1, 0, 0, 0, 255, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 6, 1, 0, 0, 0])
AES_KEY = 'UKu52ePUBwetZ9wNX88o54dnfKRu0T1l'.encode('utf-8')

# 确保密钥是32字节（AES-256）
if len(AES_KEY) != 32:
    AES_KEY = AES_KEY.ljust(32, b'\0')[:32]

# 自定义 Base64 编码解码函数（来自第一个JS文件）
def base64_encode(buffer):
    """自定义Base64编码函数"""
    if isinstance(buffer, (list, tuple)):
        buffer = bytes(buffer)
    elif not isinstance(buffer, (bytes, bytearray)):
        raise TypeError("Buffer must be bytes-like object")
    
    buffer = bytearray(buffer)
    output_length = math.ceil(math.ceil(len(buffer) * 4 / 3) / 4) * 4
    output = bytearray(output_length)
    continuous = (len(buffer) // 3) * 3
    
    for i in range(0, continuous, 3):
        k = 4 * i // 3
        output[k] = BASE64_ENCODE_TABLE[buffer[i] >> 2]
        output[k+1] = BASE64_ENCODE_TABLE[((buffer[i] & 0x03) << 4) | (buffer[i+1] >> 4)]
        output[k+2] = BASE64_ENCODE_TABLE[((buffer[i+1] & 0x0F) << 2) | (buffer[i+2] >> 6)]
        output[k+3] = BASE64_ENCODE_TABLE[buffer[i+2] & 0x3F]
    
    if continuous < len(buffer):
        k = 4 * continuous // 3
        output[k] = BASE64_ENCODE_TABLE[buffer[continuous] >> 2]
        
        if continuous + 1 < len(buffer):
            output[k+1] = BASE64_ENCODE_TABLE[((buffer[continuous] & 0x03) << 4) | (buffer[continuous+1] >> 4)]
            output[k+2] = BASE64_ENCODE_TABLE[(buffer[continuous+1] & 0x0F) << 2]
        else:
            output[k+1] = BASE64_ENCODE_TABLE[(buffer[continuous] & 0x03) << 4]
            output[k+2] = BASE64_ENCODE_TABLE[64]  # '='
        
        output[k+3] = BASE64_ENCODE_TABLE[64]  # '='
    
    return bytes(output)

def base64_decode(buffer):
    """自定义Base64解码函数"""
    if isinstance(buffer, (list, tuple)):
        buffer = bytes(buffer)
    elif not isinstance(buffer, (bytes, bytearray, str)):
        raise TypeError("Buffer must be bytes-like object or string")
    
    # Convert string to bytes if needed
    if isinstance(buffer, str):
        buffer = buffer.encode('ascii')
    
    buffer = bytearray(buffer)
    # Map to decode table values and find padding
    decoded_buffer = []
    for v in buffer:
        if v in BASE64_DECODE_TABLE:
            decoded_buffer.append(BASE64_DECODE_TABLE[v])
    
    # Find padding and truncate
    try:
        padding_index = decoded_buffer.index(64)
        decoded_buffer = decoded_buffer[:padding_index]
    except ValueError:
        pass  # No padding found
    
    output_length = 3 * len(decoded_buffer) // 4
    output = bytearray(output_length)
    continuous = (len(decoded_buffer) // 4) * 4
    
    for i in range(0, continuous, 4):
        k = 3 * i // 4
        output[k] = (decoded_buffer[i] << 2) | (decoded_buffer[i+1] >> 4)
        output[k+1] = ((decoded_buffer[i+1] & 0x0F) << 4) | (decoded_buffer[i+2] >> 2)
        output[k+2] = ((decoded_buffer[i+2] & 0x03) << 6) | decoded_buffer[i+3]
    
    if continuous < len(decoded_buffer):
        k = 3 * continuous // 4
        output[k] = (decoded_buffer[continuous] << 2) | (decoded_buffer[continuous+1] >> 4)
        
        if continuous + 2 < len(decoded_buffer):
            output[k+1] = ((decoded_buffer[continuous+1] & 0x0F) << 4) | (decoded_buffer[continuous+2] >> 2)
    
    return bytes(output)

# AES 加密解密类（来自第二个JS文件）
class AESCipher:
    def __init__(self, key):
        self.key = key
        self.backend = default_backend()
    
    def encrypt(self, data):
        # ECB模式不需要IV
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # PKCS7填充
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def decrypt(self, encrypted_data):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # 解密
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # 去除PKCS7填充
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return unpadded_data

# 初始化AES加密器
aes_cipher = AESCipher(AES_KEY)

# 字符串与字节转换函数（来自第二个JS文件）
def string_to_bytes(string):
    """将字符串转换为字节"""
    return string.encode('utf-8')

def bytes_to_string(bytes_data):
    """将字节转换为字符串"""
    return bytes_data.decode('utf-8')

# AES 加解密函数（来自第二个JS文件）
def aes_decrypt(bytes_data):
    """AES解密并移除PKCS7填充"""
    return aes_cipher.decrypt(bytes_data)

def aes_encrypt(bytes_data):
    """PKCS7填充并AES加密"""
    return aes_cipher.encrypt(bytes_data)

# C# 兼容的长度前缀编码（来自第二个JS文件）
def generate_length_prefixed_string(length):
    """生成C#兼容的长度前缀字符串"""
    length = min(0x7FFFFFFF, length)  # 最大值
    
    bytes_list = []
    for i in range(4):
        if length >> 7 != 0:
            bytes_list.append(length & 0x7F | 0x80)
            length >>= 7
        else:
            bytes_list.append(length & 0x7F)
            length >>= 7
            break
    
    if length != 0:
        bytes_list.append(length)
    
    return bytes(bytes_list)

# 头部处理函数（来自第二个JS文件）
def add_header(bytes_data):
    """添加C#头部"""
    length_data = generate_length_prefixed_string(len(bytes_data))
    
    # 构建新字节数组：固定头部 + 长度数据 + 原始数据 + 结束字节(11)
    new_bytes = bytearray()
    new_bytes.extend(C_SHARP_HEADER)
    new_bytes.extend(length_data)
    new_bytes.extend(bytes_data)
    new_bytes.append(11)  # 固定结束字节
    
    return bytes(new_bytes)

def remove_header(bytes_data):
    """移除头部"""
    # 移除固定C#头部和结束字节(11)
    data = bytes_data[len(C_SHARP_HEADER):-1]
    
    # 移除长度前缀头部
    length_count = 0
    for i in range(min(5, len(data))):
        length_count += 1
        if (data[i] & 0x80) == 0:
            break
    
    return data[length_count:]

# 主要编码解码函数（来自第二个JS文件，但使用自定义Base64）
def decode(bytes_data):
    """解码流程：移除头部 -> Base64解码 -> AES解密 -> 字符串"""
    data = bytes_data
    data = remove_header(data)
    data = base64_decode(data)  # 使用自定义Base64解码
    data = aes_decrypt(data)
    return bytes_to_string(data)

def encode(json_string):
    """编码流程：字符串 -> AES加密 -> Base64编码 -> 添加头部"""
    data = string_to_bytes(json_string)
    data = aes_encrypt(data)
    data = base64_encode(data)  # 使用自定义Base64编码
    # 可选：过滤换行符 data = data.replace(b'\n', b'').replace(b'\r', b'')
    return add_header(data)

# 辅助函数（来自第二个JS文件）
def hash_string(string):
    """字符串哈希函数（类似DJB2算法）"""
    hash_value = 0
    for char in string:
        hash_value = ((hash_value << 5) - hash_value) + ord(char)
        # 限制为32位整数
        hash_value &= 0xFFFFFFFF
    return hash_value

def round_value(value, precision):
    """四舍五入到指定精度"""
    multiplier = 10 ** precision
    return round(value * multiplier) / multiplier


def read_and_decode_file(file_path):
    """读取文件并解码打印JSON内容"""
    try:
        # 读取文件内容
        with open(file_path, 'rb') as f:
            encoded_data = f.read()
        
        print(f"已读取文件: {file_path}")
        print(f"文件大小: {len(encoded_data)} 字节")
        
        # 解码数据
        decoded_string = decode(encoded_data)
        
        # 尝试解析为JSON并漂亮打印
        try:
            with open(file_path,'w',encoding='utf-8') as f:
                json_data = json.loads(decoded_string)
                json.dump(json_data,f, indent=2, ensure_ascii=False)
                print("解码后的JSON内容已保存到 %s" % file_path)
        except json.JSONDecodeError:
            # 如果不是有效的JSON，直接打印原始字符串
            print(decoded_string)
        
        print("-" * 50)
        
        return decoded_string
    except FileNotFoundError:
        print(f"错误: 文件 '{file_path}' 未找到")
        return None
    except Exception as e:
        print(f"解码过程中出错: {e}")
        return None


def read_and_encode_file(file_path):
    """读取JSON文件并编码打印编码后的内容"""
    try:
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8') as f:
            json_content = f.read()
        
        print(f"已读取JSON文件: {file_path}")
        print(f"文件大小: {len(json_content)} 字符")
        
        # 验证JSON格式
        try:
            json_data = json.loads(json_content)
            print("JSON格式验证: 有效")
        except json.JSONDecodeError as e:
            print(f"JSON格式验证: 无效 - {e}")
            # 仍然尝试编码，但警告用户
            print("警告: JSON格式无效,但仍将尝试编码")
        
        # 编码数据
        encoded_data = encode(json_content)
        
        print("-" * 50)
        print(f"编码后数据大小: {len(encoded_data)} 字节")
        
        with open(file_path, 'wb') as f:
            f.write(encoded_data)
        print(f"编码后的数据已保存到: {file_path}")
        
        return encoded_data
        
    except FileNotFoundError:
        print(f"错误: 文件 '{file_path}' 未找到")
        return None
    except Exception as e:
        print(f"编码过程中出错: {e}")
        return None

def fix_save_file(file_path):
    """将文档解码编辑后修改，然后重新编码"""
    try:
         # 读取文件内容
        with open(file_path, 'rb') as f:
            encoded_data = f.read()
        
        print(f"已读取文件: {file_path}")
        print(f"文件大小: {len(encoded_data)} 字节")
        
        # 解码数据
        decoded_string = decode(encoded_data)

        data = json.loads(decoded_string)
        #print(data['playerData']['permadeathMode'])
        data['playerData']['permadeathMode'] = 1
        data_str = json.dumps(data, ensure_ascii=False, indent=2)

        # 重新编码
        encoded_data = encode(data_str)
        
        print("-" * 50)
        print(f"编码后数据大小: {len(encoded_data)} 字节")
        
        with open(file_path, 'wb') as f:
            f.write(encoded_data)
        print(f"编码后的数据已保存到: {file_path}")

    except FileNotFoundError:
        print(f"错误: 文件 '{file_path}' 未找到")
        return None

    
class AESBase64GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("空洞骑士编解码工具")
        self.root.geometry("400x150")
        self.root.resizable(False, False)

        # ---- 文件选择 ----
        frm_file = ttk.Frame(root)
        frm_file.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(frm_file, text="文件:").pack(side=tk.LEFT)
        self.var_path = tk.StringVar()
        ttk.Entry(frm_file, textvariable=self.var_path, width=35).pack(side=tk.LEFT, padx=5)
        ttk.Button(frm_file, text="浏览…", command=self.browse).pack(side=tk.LEFT)

        # ---- 操作选择 ----
        frm_op = ttk.Frame(root)
        frm_op.pack(fill=tk.X, padx=10)
        self.var_op = tk.StringVar(value="decode")
        ttk.Radiobutton(frm_op, text="存档解码", variable=self.var_op, value="decode").pack(side=tk.LEFT)
        ttk.Radiobutton(frm_op, text="存档编码", variable=self.var_op, value="encode").pack(side=tk.LEFT, padx=20)
        ttk.Radiobutton(frm_op, text="拯救碎心", variable=self.var_op, value="fix").pack(side=tk.LEFT, padx=40)

        # ---- 按钮与状态 ----
        frm_btn = ttk.Frame(root)
        frm_btn.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(frm_btn, text="执行", command=self.run).pack(side=tk.LEFT)
        ttk.Button(frm_btn, text="退出", command=root.quit).pack(side=tk.RIGHT)
        self.var_status = tk.StringVar(value="就绪")
        ttk.Label(frm_btn, textvariable=self.var_status).pack(side=tk.LEFT, padx=10)

    # ---------- 功能 ----------
    def browse(self):
        path = filedialog.askopenfilename(title="选择要处理的文件")
        if path:
            self.var_path.set(path)

    def run(self):
        path = self.var_path.get()
        if not os.path.isfile(path):
            messagebox.showwarning("提示", "请先选择有效文件")
            return

        self.var_status.set("处理中…")
        self.root.update()

        try:
            if self.var_op.get() == "decode":
                read_and_decode_file(path)          # 原地覆盖为解码后的 JSON
            if self.var_op.get() == "encode":
                read_and_encode_file(path)          # 原地覆盖为编码后的二进制
            if self.var_op.get() == "fix":
                fix_save_file(path)                 # 原地覆盖为修复后的二进制
            self.var_status.set("完成")
        except Exception as e:
            messagebox.showerror("错误", str(e))
            self.var_status.set("出错")
# 主函数
def main():
    # 创建主窗口
    root = tk.Tk()
    
    # 设置窗口图标（如果有的话）
    try:
        root.iconbitmap("icon.ico")  # 如果有图标文件的话
    except:
        pass
    
    # 创建应用程序
    app = AESBase64GUI(root)
    
    # 启动主循环
    root.mainloop()

# 测试代码
if __name__ == "__main__":
    main()
    # 如果有命令行参数，尝试解码指定文件
    if len(sys.argv) >= 3:
        operation = sys.argv[1].lower()
        file_path = sys.argv[2]
        
        if operation == "decode":
            read_and_decode_file(file_path)
        elif operation == "encode":
            read_and_encode_file(file_path)
        elif operation == "fix":
            fix_save_file(file_path)
        else:
            print(f"错误: 未知操作 '{operation}'")
    else:
        print("请提供要解码的文件路径作为命令行参数。")