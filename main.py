import sqlite3
import hmac
import hashlib
import secrets
from contextlib import contextmanager
from typing import Optional, List
from datetime import datetime
import time
DATABASE_PATH = 'card_system.db'
INIT_SCRIPT = """
CREATE TABLE IF NOT EXISTS cards (
    card_id TEXT PRIMARY KEY,
    raw_part TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,
    usage_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_raw_part ON cards(raw_part);
CREATE INDEX IF NOT EXISTS idx_created_at ON cards(created_at);
"""

class CardSystem:
    def __init__(self):
        self._init_db()
        self.key = self._load_or_generate_key()

    @contextmanager
    def _db_connection(self):
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._db_connection() as conn:
            conn.executescript(INIT_SCRIPT)
            conn.commit()

    def _load_or_generate_key(self) -> bytes:
        """
        安全密钥管理方案：
        去你大爷的
        """
        with self._db_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value BLOB)")
            result = conn.execute("SELECT value FROM secrets WHERE name='hmac_key'").fetchone()            
            if result:
                return result['value']
            
            new_key = secrets.token_bytes(32)
            conn.execute("INSERT INTO secrets (name, value) VALUES (?, ?)",
                        ('hmac_key', new_key))
            conn.commit()
            return new_key

    def generate_card(self, batch_size: int = 100) -> str:
        charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
        attempts = 0
        max_attempts = 5

        while attempts < max_attempts:
            cards = []
            for _ in range(batch_size):
                raw = ''.join(secrets.choice(charset) for _ in range(16))
                signature = hmac.new(self.key, raw.encode(), 'sha3_256').hexdigest()[:10]
                cards.append((f"{raw}#{signature}", raw, signature))

            try:
                with self._db_connection() as conn:
                    conn.executemany(
                        "INSERT INTO cards (card_id, raw_part, signature) VALUES (?, ?, ?)",
                        cards
                    )
                    conn.commit()
                return cards[0][0]
            except sqlite3.IntegrityError:
                attempts += 1
                continue
        
        raise RuntimeError("无法生成唯一卡密")

    def verify_card(self, card: str) -> dict:
        """
        完整验证流程（返回详细状态）：
        1. 格式验证
        2. 签名验证
        3. 数据库状态检查                                 
        """

        result = {
            'valid': False,
            'is_used': None,
            'usage_count': 0,
            'error': None
        }
        if '#' not in card:
            result['error'] = "无效卡密格式"
            return result
            
        raw, sign = card.split('#', 1)
        if len(raw) != 16 or len(sign) != 10:
            result['error'] = "长度不符合要求"
            return result
        expected_sign = hmac.new(self.key, raw.encode(), 'sha3_256').hexdigest()[:10]
        if not hmac.compare_digest(sign, expected_sign):
            result['error'] = "签名验证失败"
            return result
        try:
            with self._db_connection() as conn:
                row = conn.execute(
                    "SELECT is_used, usage_count FROM cards WHERE card_id = ?",
                    (card,)
                ).fetchone()
                
                if not row:
                    result['error'] = "卡密不存在"
                    return result
                
                result.update({
                    'valid': True,
                    'is_used': bool(row['is_used']),
                    'usage_count': row['usage_count']
                })
        except sqlite3.Error as e:
            result['error'] = f"数据库错误: {str(e)}"
        
        return result

    def mark_as_used(self, card: str) -> bool:
        """
        标记卡密为已使用（支持多次使用计数）
        """
        with self._db_connection() as conn:
            try:
                conn.execute(
                    """UPDATE cards 
                       SET is_used = TRUE, 
                           used_at = CURRENT_TIMESTAMP,
                           usage_count = usage_count + 1 
                       WHERE card_id = ?""",
                    (card,)
                )
                conn.commit()
                return conn.total_changes > 0
            except sqlite3.Error:
                return False

    def get_card_stats(self) -> dict:
        """获取系统统计信息"""
        with self._db_connection() as conn:
            stats = conn.execute("""
                SELECT 
                    COUNT(*) AS total,
                    SUM(is_used) AS used_count,
                    SUM(usage_count) AS total_uses,
                    MIN(created_at) AS oldest,
                    MAX(created_at) AS newest
                FROM cards
            """).fetchone()
            
            return dict(stats) if stats else {}
if __name__ == "__main__":
    system = CardSystem()
    new_card = system.generate_card()
    print(f"生成新卡密: {new_card}")
    verification = system.verify_card(new_card)
    print(f"验证结果: {verification}")
    print("卡密尚未标记为使用")
    print("\n系统统计:")
    print(system.get_card_stats())
    print("输入卡密来验证:")
    n = input()
    v = system.verify_card(n)
    print(f"验证结果: {v}")
    time.sleep(3)
    if v['valid'] and not v['is_used']:
        print("卡密未在库中")
        print("是否标记为使用？：(y or n)")
        s = input()
        if s == "y" :
            system.mark_as_used(n)
            print("卡密已在库中（十秒后关闭）")
            time.sleep(10)
        if s == "n" :
            print("卡密尚未标记在库中（十秒后关闭）")
            time.sleep(10)
