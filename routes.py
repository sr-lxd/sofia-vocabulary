import base64
import json
import logging
import random
import secrets
import hashlib
import hmac
from io import BytesIO
from datetime import datetime, timedelta, timezone
from threading import Lock
from queue import Queue, Empty

# 北京时区（UTC+8）
BEIJING_TZ = timezone(timedelta(hours=8))

# 格式化时间差显示
def format_time_diff(total_seconds):
    """将总秒数格式化为详细的时间显示"""
    if total_seconds < 0:
        return "刚刚"
    
    total_minutes = int(total_seconds / 60)
    days = total_minutes // (24 * 60)
    hours = (total_minutes % (24 * 60)) // 60
    minutes = total_minutes % 60
    
    result = "距首次"
    parts = []
    
    if days > 0:
        parts.append(f"{days}天")
    if hours > 0:
        parts.append(f"{hours}小时")
    if minutes > 0 or len(parts) == 0:
        parts.append(f"{minutes}分钟")
    
    return result + "".join(parts)

def now_beijing():
    """获取北京时间"""
    return datetime.now(BEIJING_TZ)

from flask import render_template, request, jsonify, send_file, Response, stream_with_context, current_app, session
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_, func, text, bindparam
from sqlalchemy.exc import IntegrityError

from . import vocab_bp
from .models import User, UserPref, DeckWord, ReviewState, WordClickStat
from extensions import db
from math import ceil
from typing import Optional, Tuple

# ======================= 会话自动续期 =======================
@vocab_bp.before_request
def renew_session():
    """
    在每次请求时自动续期会话，防止用户在活跃使用时被登出。
    Flask的session需要标记为permanent才会应用PERMANENT_SESSION_LIFETIME。
    """
    if current_user.is_authenticated:
        session.permanent = True  # 标记会话为永久会话，使用PERMANENT_SESSION_LIFETIME配置
        session.modified = True   # 强制更新会话过期时间

# ======================= 通用大小写无关匹配 =======================
def ci_like(column, needle: str):
    """跨数据库的大小写无关 LIKE：LOWER(column) LIKE LOWER('%needle%')。"""
    needle = (needle or "").lower()
    return func.lower(column).like(f"%{needle}%")

def ci_eq(column, value: str):
    """跨数据库的大小写无关等值：LOWER(column) == LOWER(:v)。"""
    return func.lower(column) == func.lower(bindparam("v", (value or "")))

# ======================= Bootstrap 缓存系统 =======================
_bootstrap_cache = {}  # uid -> {"data": {...}, "expires_at": timestamp}
_bootstrap_cache_lock = Lock()
BOOTSTRAP_CACHE_TTL = 5  # 5秒缓存

def _get_bootstrap_cache(uid: int):
    """获取缓存的 bootstrap 数据"""
    with _bootstrap_cache_lock:
        if uid in _bootstrap_cache:
            cache_entry = _bootstrap_cache[uid]
            if now_beijing().timestamp() < cache_entry["expires_at"]:
                return cache_entry["data"]
            else:
                del _bootstrap_cache[uid]
    return None

def _set_bootstrap_cache(uid: int, data: dict):
    """设置 bootstrap 缓存"""
    with _bootstrap_cache_lock:
        _bootstrap_cache[uid] = {
            "data": data,
            "expires_at": now_beijing().timestamp() + BOOTSTRAP_CACHE_TTL
        }

# ======================= 安全快捷登录系统 =======================
# 快捷登录令牌缓存（内存）
_quick_login_tokens = {}
# 多进程兼容：避免全局锁，使用函数级锁
def get_quick_login_lock():
    """获取快速登录锁，避免多进程全局锁问题"""
    if not hasattr(get_quick_login_lock, '_lock'):
        get_quick_login_lock._lock = Lock()
    return get_quick_login_lock._lock
_quick_login_attempts = {}  # IP -> (attempts, last_attempt_time)
_csrf_tokens = {}  # session_id -> csrf_token

# 预设账户配置
PRESET_ACCOUNTS = {
    # Add local demo accounts here only when you create unique credentials.
}

def generate_csrf_token() -> str:
    """生成CSRF令牌"""
    return secrets.token_hex(32)

def get_or_create_csrf_token() -> str:
    """获取或创建当前会话的CSRF令牌"""
    from flask import session
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()
    return session['csrf_token']

def validate_csrf_token(token: str) -> bool:
    """验证CSRF令牌"""
    from flask import session
    expected_token = session.get('csrf_token')
    if not expected_token or not token:
        return False
    return hmac.compare_digest(token, expected_token)

def generate_quick_login_token(username: str, client_ip: str) -> str:
    """生成安全的快捷登录令牌"""
    # 验证是否为预设账户
    if username not in PRESET_ACCOUNTS:
        raise ValueError(f"未授权的预设账户: {username}")
    
    # 生成令牌
    timestamp = str(int(now_beijing().timestamp()))
    nonce = secrets.token_hex(16)
    
    # 创建签名数据
    data = f"{username}:{client_ip}:{timestamp}:{nonce}"
    
    # 使用应用密钥生成HMAC签名（这里使用固定密钥，生产环境应从配置读取）
    secret_key = str(current_app.config["SECRET_KEY"])
    signature = hmac.new(
        secret_key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    token = f"{username}.{timestamp}.{nonce}.{signature}"
    
    # 缓存令牌（5分钟有效期）
    with get_quick_login_lock():
        # 清理过期令牌
        current_time = int(now_beijing().timestamp())
        expired_tokens = [
            t for t, info in _quick_login_tokens.items() 
            if current_time - info['created_at'] > 300  # 5分钟
        ]
        for expired_token in expired_tokens:
            _quick_login_tokens.pop(expired_token, None)
        
        # 存储新令牌
        _quick_login_tokens[token] = {
            'username': username,
            'client_ip': client_ip,
            'created_at': current_time,
            'used': False
        }
    
    return token

def validate_quick_login_token(token: str, client_ip: str) -> Tuple[bool, str]:
    """验证快捷登录令牌"""
    try:
        # 解析令牌
        parts = token.split('.')
        if len(parts) != 4:
            return False, "令牌格式无效"
        
        username, timestamp, nonce, signature = parts
        
        # 验证时间戳
        token_time = int(timestamp)
        current_time = int(now_beijing().timestamp())
        if current_time - token_time > 300:  # 5分钟过期
            return False, "令牌已过期"
        
        # 重新计算签名验证
        data = f"{username}:{client_ip}:{timestamp}:{nonce}"
        secret_key = str(current_app.config["SECRET_KEY"])
        expected_signature = hmac.new(
            secret_key.encode('utf-8'),
            data.encode('utf-8'), 
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return False, "令牌签名无效"
        
        # 检查令牌缓存
        with get_quick_login_lock():
            token_info = _quick_login_tokens.get(token)
            if not token_info:
                return False, "令牌不存在"
            
            if token_info['used']:
                return False, "令牌已使用"
            
            if token_info['client_ip'] != client_ip:
                return False, "IP地址不匹配"
            
            # 标记令牌为已使用（一次性）
            token_info['used'] = True
        
        return True, username
        
    except Exception as e:
        current_app.logger.warning(f"令牌验证异常: {e}")
        return False, "令牌验证失败"

def check_rate_limit(client_ip: str) -> Tuple[bool, str]:
    """检查快捷登录速率限制"""
    current_time = now_beijing().timestamp()
    
    with get_quick_login_lock():
        if client_ip not in _quick_login_attempts:
            _quick_login_attempts[client_ip] = {'count': 0, 'last_time': current_time}
            return True, ""
        
        attempt_info = _quick_login_attempts[client_ip]
        time_diff = current_time - attempt_info['last_time']
        
        # 每小时重置计数
        if time_diff > 3600:
            attempt_info['count'] = 0
            attempt_info['last_time'] = current_time
            return True, ""
        
        # 每小时最多10次尝试
        if attempt_info['count'] >= 10:
            return False, "请求过于频繁，请稍后再试"
        
        # 相邻请求至少间隔3秒
        if time_diff < 3:
            return False, "请求过于频繁，请等待3秒"
        
        attempt_info['count'] += 1
        attempt_info['last_time'] = current_time
        
    return True, ""

# ======================= 进程内 SSE（可选） =======================
# 多进程兼容：SSE锁处理
def get_sse_lock():
    """获取SSE锁，避免多进程全局锁问题"""
    if not hasattr(get_sse_lock, '_lock'):
        get_sse_lock._lock = Lock()
    return get_sse_lock._lock
_sse_subscribers = {}  # uid -> set[Queue]

def _sse_subscribe(uid: int):
    q = Queue(maxsize=32)
    with get_sse_lock():
        _sse_subscribers.setdefault(uid, set()).add(q)
    def _unsubscribe():
        with get_sse_lock():
            try:
                _sse_subscribers.get(uid, set()).discard(q)
                if not _sse_subscribers.get(uid):
                    _sse_subscribers.pop(uid, None)
            except Exception:
                pass
    return q, _unsubscribe

def _sse_publish(uid: int, event: str, data: dict):
    payload = {"event": event, "data": data or {}}
    with get_sse_lock():
        qs = list(_sse_subscribers.get(uid, set()))
    for q in qs:
        try:
            q.put_nowait(payload)
        except Exception:
            pass

@vocab_bp.get("/api/events")
@login_required
def api_events():
    uid = current_user.id
    def gen():
        q, unsubscribe = _sse_subscribe(uid)
        try:
            yield "event: hello\ndata: {}\n\n"
            init_stats = _calc_stats_for_user(uid)
            yield f"event: stats\ndata: {json.dumps(init_stats, ensure_ascii=False)}\n\n"
            while True:
                try:
                    item = q.get(timeout=25)
                    ev = item.get("event", "message")
                    data = item.get("data", {})
                    yield f"event: {ev}\n"
                    yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
                except Empty:
                    yield ": ping\n\n"
        finally:
            unsubscribe()
    resp = Response(gen(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp

# ======================= 幂等：确保 userpref.study_pool / deck_name 列存在 =======================
def _ensure_columns(table_name: str, column_definitions: dict):
    """Add missing columns on supported SQL databases using portable inspection."""
    from sqlalchemy import inspect

    inspector = inspect(db.engine)
    if not inspector.has_table(table_name):
        return
    existing = {column["name"] for column in inspector.get_columns(table_name)}
    try:
        with db.engine.begin() as connection:
            for column_name, definition in column_definitions.items():
                if column_name not in existing:
                    connection.execute(text(
                        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
                    ))
    except Exception:
        db.session.rollback()
        raise


def _ensure_userpref_study_pool_column():
    _ensure_columns("vocab_userpref", {"study_pool": "VARCHAR(8) NOT NULL DEFAULT 'easy'"})


def _ensure_userpref_deck_name_column():
    _ensure_columns("vocab_userpref", {"deck_name": "VARCHAR(255) NOT NULL DEFAULT '未命名词库'"})


def _ensure_userpref(uid: int) -> UserPref:
    """Return the user's preference row, creating it with model defaults."""
    pref = UserPref.query.filter_by(user_id=uid).first()
    if pref is None:
        pref = UserPref(user_id=uid)
        db.session.add(pref)
    else:
        pref.study_pool = pref.study_pool or "easy"
        pref.deck_name = pref.deck_name or "未命名词库"
    db.session.commit()
    return pref
def _get_or_create_pref(uid: int) -> UserPref:
    return _ensure_userpref(uid)

# ======================= 页面 =======================
@vocab_bp.route("/")
def index_page():
    """主页面 - 重定向到登录页面"""
    return render_template("signin.html")

@vocab_bp.route("/main")
def main_page():
    """独立主页面 - 大气简洁的介绍页面"""
    return render_template("main_index.html")

@vocab_bp.route("/signin")
def signin_page():
    """独立登录页面 - Sofia背单词v2.2.3@2025.9"""
    return render_template("signin.html")


@vocab_bp.route("/app")
def app_page():
    """学单词功能页面 - 纯React应用"""
    return render_template("vocab_index.html")

@vocab_bp.get("/keepwords")
def keepwords():
    return render_template("keepwords.html")

@vocab_bp.get("/keepwords.html")
def keepwords_page():
    return render_template("keepwords.html")

# ======================= 种子词（注册后可选） =======================
SEED_WORDS = [
    {"en": "apple", "zh": "苹果"},
    {"en": "river", "zh": "河流"},
    {"en": "mountain", "zh": "山"},
    {"en": "sky", "zh": "天空"},
    {"en": "book", "zh": "书"},
]

# ======================= 认证 =======================
@vocab_bp.post("/api/register")
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    remember = data.get("remember", False)
    
    if not username or not password:
        return jsonify({"ok": False, "message": "用户名或密码不能为空"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"ok": False, "message": "用户名已存在"}), 400
    try:
        u = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(u)
        db.session.flush()
        if SEED_WORDS:
            db.session.bulk_insert_mappings(
                DeckWord,
                [{"user_id": u.id, "en": w["en"], "zh": w["zh"]} for w in SEED_WORDS],
            )
        _ensure_userpref(u.id)
        db.session.commit()
        login_user(u)
        
        # 处理服务端记住登录功能
        try:
            device_fingerprint = generate_device_fingerprint(request)
            if remember:
                import time
                pass
        except Exception as e:
            pass
        
        return jsonify({"ok": True})
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("register failed: %s", e)
        return jsonify({"ok": False, "message": f"注册失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    remember = data.get("remember", False)
    
    u = User.query.filter_by(username=username).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({"ok": False, "message": "用户名或密码错误"}), 400
    
    _ensure_userpref(u.id)
    login_user(u)
    
    # 处理服务端记住登录功能
    try:
        device_fingerprint = generate_device_fingerprint(request)
        if remember:
            import time
            pass
        else:
            # 如果没有勾选记住，清除之前保存的信息
            if device_fingerprint in _server_remember_logins:
                del _server_remember_logins[device_fingerprint]
    except Exception as e:
        pass
    
    # 主动推送完整的用户数据，避免前端竞态条件
    try:
        stats = _calc_stats_for_user(u.id)
        deck_name = db.session.execute(text(
            "SELECT COALESCE(deck_name,'未命名词库') FROM vocab_userpref WHERE user_id=:uid"
        ), {"uid": u.id}).scalar() or "未命名词库"
        
        _sse_publish(u.id, "user_switched", {
            "stats": stats,
            "deck_name": deck_name,
            "username": u.username
        })
    except Exception:
        pass
        
    return jsonify({"ok": True})

@vocab_bp.post("/api/logout")
@login_required
def api_logout():
    logout_user()
    return jsonify({"ok": True})

# ======================= 服务端记住登录功能 =======================
# 服务端记住登录信息存储（基于用户设备指纹）
_server_remember_logins = {}  # device_fingerprint -> {username, password, timestamp}

def generate_device_fingerprint(request):
    """生成设备指纹，用于跨浏览器上下文识别同一设备"""
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # 简化的设备指纹：IP + UA的哈希
    import hashlib
    fingerprint_data = f"{client_ip}:{user_agent}:{accept_language}"
    fingerprint = hashlib.md5(fingerprint_data.encode('utf-8')).hexdigest()[:16]
    return fingerprint

@vocab_bp.get("/api/get_remembered_login")
def api_get_remembered_login():
    """Legacy endpoint: server-side password storage is disabled."""
    return jsonify({"ok": True, "has_data": False})


@vocab_bp.post("/api/save_remembered_login")
def api_save_remembered_login():
    """Legacy endpoint: never store passwords on the server."""
    return jsonify({"ok": True, "saved": False})


@vocab_bp.post("/api/clear_remembered_login")
def api_clear_remembered_login():
    """Legacy endpoint: no server-side credentials are retained."""
    return jsonify({"ok": True})
# ======================= 快捷登录 API =======================
@vocab_bp.get("/api/csrf_token")
def api_csrf_token():
    """获取CSRF令牌"""
    token = get_or_create_csrf_token()
    return jsonify({"csrf_token": token})

@vocab_bp.get("/api/quick_login_accounts")
def api_quick_login_accounts():
    """获取可用的快捷登录账户列表"""
    accounts = []
    for username, info in PRESET_ACCOUNTS.items():
        accounts.append({
            'username': username,
            'display': info['display']
        })
    return jsonify({"ok": True, "accounts": accounts})

@vocab_bp.post("/api/generate_quick_login_token")  
def api_generate_quick_login_token():
    """生成快捷登录令牌"""
    try:
        data = request.get_json(silent=True) or {}
        
        # 验证CSRF令牌
        csrf_token = data.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not csrf_token or not validate_csrf_token(csrf_token):
            return jsonify({"ok": False, "message": "CSRF令牌验证失败"}), 403
        
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not client_ip:
            return jsonify({"ok": False, "message": "无法获取客户端IP"}), 400
            
        # 检查速率限制
        allowed, error_msg = check_rate_limit(client_ip)
        if not allowed:
            return jsonify({"ok": False, "message": error_msg}), 429
            
        username = (data.get("username") or "").strip()
        
        if not username:
            return jsonify({"ok": False, "message": "用户名不能为空"}), 400
            
        # 生成令牌
        token = generate_quick_login_token(username, client_ip)
        
        return jsonify({
            "ok": True, 
            "token": token,
            "expires_in": 300,  # 5分钟
            "message": "令牌生成成功，请在5分钟内使用"
        })
        
    except ValueError as e:
        return jsonify({"ok": False, "message": str(e)}), 400
    except Exception as e:
        current_app.logger.exception("生成快捷登录令牌失败: %s", e)
        return jsonify({"ok": False, "message": "服务器错误"}), 500

@vocab_bp.post("/api/quick_login_with_token")
def api_quick_login_with_token():
    """使用令牌进行快捷登录"""
    try:
        data = request.get_json(silent=True) or {}
        
        # 验证CSRF令牌
        csrf_token = data.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not csrf_token or not validate_csrf_token(csrf_token):
            return jsonify({"ok": False, "message": "CSRF令牌验证失败"}), 403
        
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not client_ip:
            return jsonify({"ok": False, "message": "无法获取客户端IP"}), 400
            
        token = (data.get("token") or "").strip()
        
        if not token:
            return jsonify({"ok": False, "message": "令牌不能为空"}), 400
            
        # 验证令牌
        valid, result = validate_quick_login_token(token, client_ip)
        if not valid:
            return jsonify({"ok": False, "message": result}), 400
            
        username = result
        
        # 查找或创建用户
        u = User.query.filter_by(username=username).first()
        if not u:
            try:
                # 创建预设账户
                preset_info = PRESET_ACCOUNTS[username]
                u = User(username=username, password_hash=generate_password_hash(preset_info['password']))
                db.session.add(u)
                db.session.flush()
                _ensure_userpref(u.id)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("创建预设账户失败: %s", e)
                return jsonify({"ok": False, "message": "账户创建失败"}), 500
        
        # 确保用户偏好设置存在
        _ensure_userpref(u.id)
        login_user(u)
        
        # 快捷登录也使用服务端记住功能（保存预设账户信息）
        try:
            device_fingerprint = generate_device_fingerprint(request)
            import time
            pass
        except Exception as e:
            pass
        
        # 主动推送完整的用户数据，避免前端竞态条件
        try:
            stats = _calc_stats_for_user(u.id)
            deck_name = db.session.execute(text(
                "SELECT COALESCE(deck_name,'未命名词库') FROM vocab_userpref WHERE user_id=:uid"
            ), {"uid": u.id}).scalar() or "未命名词库"
            
            _sse_publish(u.id, "user_switched", {
                "stats": stats,
                "deck_name": deck_name,
                "username": u.username
            })
        except Exception:
            pass
        
        return jsonify({
            "ok": True, 
            "message": "登录成功",
            "username": u.username
        })
        
    except Exception as e:
        current_app.logger.exception("快捷登录失败: %s", e)
        return jsonify({"ok": False, "message": "登录失败"}), 500

@vocab_bp.get("/api/me")
def api_me():
    if current_user.is_authenticated:
        return jsonify({"logged_in": True, "username": current_user.username})
    return jsonify({"logged_in": False})

# ======================= 偏好（含 deck_name） =======================
@vocab_bp.get("/api/prefs")
@login_required
def api_get_prefs():
    p = _get_or_create_pref(current_user.id)
    sp = db.session.execute(text(
        "SELECT COALESCE(study_pool,'easy') FROM vocab_userpref WHERE user_id=:uid"
    ), {"uid": current_user.id}).scalar() or "easy"
    dn = db.session.execute(text(
        "SELECT COALESCE(deck_name,'未命名词库') FROM vocab_userpref WHERE user_id=:uid"
    ), {"uid": current_user.id}).scalar() or "未命名词库"
    return jsonify({
        "ok": True,
        "sort_mode": (p.sort_mode if p else "asc"),
        "last_en_marker": (p.last_en_marker if p else None),
        "study_pool": sp,
        "deck_name": dn,
    })

@vocab_bp.post("/api/prefs")
@login_required
def api_set_prefs():
    data = request.get_json(silent=True) or {}
    p = _get_or_create_pref(current_user.id)

    if "sort_mode" in data and p:
        mode = (data.get("sort_mode") or "asc").lower()
        if mode not in ("asc", "desc", "random"):
            return jsonify({"ok": False, "message": "sort_mode 仅支持 asc/desc/random"}), 400
        changed = (p.sort_mode != mode)
        p.sort_mode = mode
        if changed:
            p.last_en_marker = None

    if "study_pool" in data:
        pool = (data.get("study_pool") or "easy").lower()
        if pool == "all":
            pool = "easy"
        if pool not in ("easy", "good", "hard"):
            return jsonify({"ok": False, "message": "study_pool 仅支持 all/easy/good/hard"}), 400
        db.session.execute(text(
            "UPDATE vocab_userpref SET study_pool=:pool WHERE user_id=:uid"
        ), {"pool": pool, "uid": current_user.id})

    if "deck_name" in data:
        deck_name = (data.get("deck_name") or "").strip() or "未命名词库"
        deck_name = deck_name[:255]
        db.session.execute(text(
            "UPDATE vocab_userpref SET deck_name=:dn WHERE user_id=:uid"
        ), {"dn": deck_name, "uid": current_user.id})
        try:
            _sse_publish(current_user.id, "deck_meta", {"deck_name": deck_name})
        except:
            pass

    db.session.commit()
    return jsonify({"ok": True})

# ======================= 统计 =======================
def _calc_stats_for_user(uid: int):
    """优化版统计：单次聚合查询"""
    total = DeckWord.query.filter_by(user_id=uid).count()

    # 单次聚合查询统计各档数量
    # 使用 CASE WHEN 的正确语法：whens 列表
    from sqlalchemy import case

    result = db.session.query(
        func.sum(case(
            (ReviewState.last_grade == 5, 1),
            else_=0
        )).label('easy'),
        func.sum(case(
            (ReviewState.last_grade == 4, 1),
            else_=0
        )).label('good'),
        func.sum(case(
            (or_(
                and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
                and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0)
            ), 1),
            else_=0
        )).label('hard')
    ).filter(ReviewState.user_id == uid).first()

    easy = int(result.easy or 0) if result and result.easy is not None else 0
    good = int(result.good or 0) if result and result.good is not None else 0
    hard = int(result.hard or 0) if result and result.hard is not None else 0
    remain = max(0, int(total) - int(easy))

    return {
        "total": int(total), "easy": int(easy), "very_easy": int(easy),
        "good": int(good), "hard": int(hard), "again": int(hard), "remain": int(remain)
    }

@vocab_bp.get("/api/stats")
@login_required
def api_stats():
    try:
        stats = _calc_stats_for_user(current_user.id)
        pref = _get_or_create_pref(current_user.id)
        return jsonify({"ok": True, **stats, "rev": int((pref.stats_rev if pref else 0) or 0)})
    except Exception as e:
        current_app.logger.exception("stats failed: %s", e)
        return jsonify({"ok": False, "message": f"统计失败: {type(e).__name__}: {e}"}), 500

# ======================= SRS 调度工具（提前补偿 + 到期聚合） - 优化版 =======================
_SRS_EARLY_ALPHA = 0.10
_SRS_EARLY_MAX_RATIO = 0.25
_BUCKET_SHORT_THRESHOLD = 1200
_BUCKET_SHORT_MINUTES = 2
_BUCKET_LONG_MINUTES = 10

# 缓存常用的timedelta对象
_TIMEDELTA_CACHE = {
    'short_minutes': timedelta(minutes=_BUCKET_SHORT_MINUTES),
    'one_minute': timedelta(minutes=1),
    'long_minutes': timedelta(minutes=_BUCKET_LONG_MINUTES),
}

def _apply_early_compensation(now: datetime, raw_next_due: datetime, early_seconds: int) -> datetime:
    """改进版提前补偿：仅在显著提前时才打折"""
    if early_seconds <= 0:
        return raw_next_due

    interval_seconds = int((raw_next_due - now).total_seconds())
    if interval_seconds <= 0:
        return raw_next_due

    # 宽容阈值：提前不到 40% 不打折
    if early_seconds < interval_seconds * 0.4:
        return raw_next_due

    # 超过阈值后温和打折
    ratio = min(early_seconds / interval_seconds, 1.0)
    penalty_ratio = 0.1 * (ratio - 0.4) / 0.6   # 线性：40%→0%，100%→10%
    penalty = int(interval_seconds * penalty_ratio)

    return now + timedelta(seconds=max(1, interval_seconds - penalty))


def _bucketize_due(now: datetime, due: datetime) -> datetime:
    """优化版到期聚合：减少datetime操作"""
    interval_seconds = int((due - now).total_seconds())
    
    # 使用replace一次性清零秒和微秒
    base = due.replace(second=0, microsecond=0)
    
    if interval_seconds < _BUCKET_SHORT_THRESHOLD:
        # 短间隔：如果有秒/微秒则向上取整到下一分钟
        if due.second or due.microsecond:
            base += _TIMEDELTA_CACHE['short_minutes']
        return base
    else:
        # 长间隔：先向上取整到下一分钟，再对齐到5分钟边界
        if due.second or due.microsecond:
            base += _TIMEDELTA_CACHE['one_minute']
        
        m_mod = base.minute % _BUCKET_LONG_MINUTES
        if m_mod != 0:
            base += timedelta(minutes=(_BUCKET_LONG_MINUTES - m_mod))
        return base

# ================ 评分映射 & 间隔计算（3→5 档 + 小时/天/周取整） ================
def estimate_read_ms(def_len_chars: int, device: str = "desktop", cps: Optional[float] = None) -> int:
    """估算阅读释义所需时间（毫秒）。中文约 7 cps，移动端略慢。"""
    base_cps = cps if cps else 7.0
    ms = max(2000, ceil((def_len_chars or 0) / base_cps * 1000))
    if device != "desktop":
        ms = int(ms * 1.2)
    return ms

def _round_unit_hours(hours: float) -> float:
    """小间隔用 0.5h/1h，天/周级按 1d/1w 对齐。"""
    if hours < 6:
        unit = 0.5
    elif hours < 24:
        unit = 1.0
    elif hours < 24 * 14:
        unit = 24.0
    else:
        unit = 24.0 * 7
    return max(unit, round(hours / unit) * unit)

def compute_next_interval(last_interval_h: Optional[float], grade: int) -> float:
    """
    1=again, 2=hard, 3=good, 4=easy, 5=very easy
    采用“起始间隔+增长因子”，并按小时/天/周取整，以拉开 hard/good/easy 频率。
    """
    I0   = {1: 0.5, 2: 1, 3: 3, 4: 24, 5: 48}         # 小时
    grow = {1: 0.5, 2: 1.8, 3: 2.3, 4: 3.0, 5: 4.0}   # again 为回退 0.5×
    min_h = {1: 0.5, 2: 1, 3: 2, 4: 24, 5: 48}
    max_h = {1: 24, 2: 72, 3: 24 * 14, 4: 24 * 180, 5: 24 * 365}

    if not last_interval_h or last_interval_h <= 0:
        nxt = I0[grade]
    else:
        nxt = max(min_h[1], last_interval_h * grow[1]) if grade == 1 else last_interval_h * grow[grade]

    nxt = _round_unit_hours(nxt)
    return max(min_h[grade], min(nxt, max_h[grade]))

def map_ui_to_grade(
    ui: str,
    rt_total_ms: int,
    used_reveal: bool,
    pre_reveal_ms: int,
    def_dwell_ms: int,
    def_len_chars: int,
    consec_easy: int,
    hard_streak: int,
    last_interval_h: Optional[float],
    device: str = "desktop"
) -> int:
    """
    极简宽容版评分逻辑：
    - 不因看释义时间而降分；
    - “容易”始终≥4；
    - 连续或快速“容易”晋级熟记(5)；
    - 优先尊重用户主观选择。
    """
    T_VE_SHORT   = 4000 if device == "desktop" else 5000   # 快速点击阈值
    T_AGAIN_LONG = 20000 if device == "desktop" else 25000

    est_ms = estimate_read_ms(def_len_chars or 0, device)
    dwell_ratio = (def_dwell_ms / est_ms) if used_reveal and est_ms > 0 else 0.0
    last_h = float(last_interval_h or 0.0)

    # again（1）
    if ui == "hard" and (
        rt_total_ms >= T_AGAIN_LONG
        or hard_streak >= 2
        or last_h >= 24
    ):
        return 1

    # hard（2）
    if ui == "hard":
        return 2

    # good（3）
    if ui == "good":
        return 3

    # easy（4/5）
    if ui == "easy":
        # 8秒内点击直接得5分
        if rt_total_ms <= 8000:
            return 5
        # 8秒外，满足以下条件之一也得5分
        if consec_easy >= 1 or last_h >= 24 * 3:  # 连续1次点容易 或 间隔>=3天
            return 5
        return 4

# ======================= 学习概览（到期提示） =======================
@vocab_bp.get("/api/session_hint")
@login_required
def api_session_hint():
    uid = current_user.id
    now = datetime.utcnow()

    req_pool = (request.args.get("pool") or "").lower().strip()
    if req_pool == "all":
        req_pool = "easy"
    if req_pool not in ("easy", "good", "hard"):
        req_pool = db.session.execute(text(
            "SELECT COALESCE(study_pool,'easy') FROM vocab_userpref WHERE user_id=:uid"
        ), {"uid": uid}).scalar() or "easy"
    pool = req_pool

    base_q = db.session.query(ReviewState).filter(ReviewState.user_id == uid)
    if pool == "good":
        base_q = base_q.filter(ReviewState.last_grade == 4)
    elif pool == "hard":
        base_q = base_q.filter(or_(
            and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),             
            and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0),
        ))

    due_now = base_q.filter(ReviewState.next_due <= now).with_entities(func.count(ReviewState.id)).scalar() or 0

    next_due_time = base_q.filter(ReviewState.next_due > now).with_entities(func.min(ReviewState.next_due)).scalar()
    if next_due_time:
        eta = max(0, int((next_due_time - now).total_seconds()))
        next_due_iso = next_due_time.replace(microsecond=0).isoformat() + "Z"
    else:
        eta = 0
        next_due_iso = None

    day_end = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=0)
    due_today_left = base_q.filter(
        and_(ReviewState.next_due > now, ReviewState.next_due <= day_end)
    ).with_entities(func.count(ReviewState.id)).scalar() or 0

    return jsonify({
        "ok": True,
        "pool": pool,
        "due_now": int(due_now),
        "due_next_eta_sec": int(eta),
        "due_next_time": next_due_iso,
        "due_today_left": int(due_today_left),
    })

# ======================= 词库接口（含 deck_meta & 载入词库修复） =======================
@vocab_bp.get("/api/deck_meta")
@login_required
def api_deck_meta():
    dn = db.session.execute(text(
        "SELECT COALESCE(deck_name,'未命名词库') FROM vocab_userpref WHERE user_id=:uid"
    ), {"uid": current_user.id}).scalar() or "未命名词库"
    stats = _calc_stats_for_user(current_user.id)
    return jsonify({"ok": True, "deck_name": dn, **stats})

@vocab_bp.get("/api/words")
@login_required
def api_words():
    try:
        words = DeckWord.query.filter_by(user_id=current_user.id).order_by(DeckWord.en.asc()).all()
        return jsonify([{"id": w.id, "en": w.en, "zh": w.zh} for w in words])
    except Exception as e:
        current_app.logger.exception("words failed: %s", e)
        return jsonify({"ok": False, "message": f"words 查询失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.get("/api/word_detail/<int:word_id>")
@login_required
def api_word_detail(word_id):
    """获取单个词汇的完整信息"""
    try:
        word = DeckWord.query.filter_by(id=word_id, user_id=current_user.id).first()
        if not word:
            return jsonify({"ok": False, "message": "词汇不存在"}), 404
        
        # 返回完整的词汇信息
        word_info = {
            "id": word.id,
            "en": word.en,
            "zh": word.zh
        }
        
        # 安全地处理时间字段
        if hasattr(word, 'created_at') and word.created_at:
            # 确保时间是带时区的
            if word.created_at.tzinfo is None:
                # 如果是naive datetime，假设它是北京时间
                word_info["created_at"] = word.created_at.replace(tzinfo=BEIJING_TZ).strftime("%Y-%m-%d %H:%M")
            else:
                word_info["created_at"] = word.created_at.astimezone(BEIJING_TZ).strftime("%Y-%m-%d %H:%M")
        
        # 检查是否有updated_at字段
        if hasattr(word, 'updated_at') and word.updated_at:
            if word.updated_at.tzinfo is None:
                word_info["updated_at"] = word.updated_at.replace(tzinfo=BEIJING_TZ).strftime("%Y-%m-%d %H:%M")
            else:
                word_info["updated_at"] = word.updated_at.astimezone(BEIJING_TZ).strftime("%Y-%m-%d %H:%M")
        
        return jsonify({
            "ok": True,
            "word": word_info
        })
    except Exception as e:
        current_app.logger.exception("word_detail failed: %s", e)
        return jsonify({"ok": False, "message": f"获取词汇详情失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.get("/api/words_cache")
@login_required
def api_words_cache():
    """
    供前端“即输即现”的本地检索缓存：
    返回字段包含 last_grade / wrong_count，方便前端按 pool 过滤。
    """
    uid = current_user.id
    rows = (db.session.query(DeckWord, ReviewState)
            .outerjoin(ReviewState, (ReviewState.user_id == uid) & (ReviewState.deckword_id == DeckWord.id))
            .filter(DeckWord.user_id == uid)
            .order_by(func.lower(DeckWord.en).asc())
            .all())
    items = []
    for w, st in rows:
        items.append({
            "id": w.id,
            "en": w.en,
            "zh": w.zh,
            "last_grade": (int(st.last_grade) if (st is not None and st.last_grade is not None) else None),
            "wrong_count": (int(st.wrong_count) if (st is not None and st.wrong_count is not None) else 0),

        })
    return jsonify({"ok": True, "items": items})

@vocab_bp.post("/api/custom_words")
@login_required
def api_custom_words():
    """
    载入（覆盖）词库：
    - 清空 DeckWord 与 ReviewState
    - 批量写入新词（去重）
    - 同步保存/返回 deck_name（作为“权威词库名”）
    """
    data = request.get_json(silent=True) or {}
    raw = data.get("words")
    if not isinstance(raw, list):
        return jsonify({"ok": False, "message": "格式错误，应为包含对象的数组"}), 400

    deck_name = (data.get("deck_name") or "").strip() or "未命名词库"
    deck_name = deck_name[:255]

    cleaned, seen = [], set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        en = str(item.get("en", "")).strip()
        zh = str(item.get("zh", "")).strip()
        if not en or not zh:
            continue
        key = en.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append({"user_id": current_user.id, "en": en, "zh": zh})

    try:
        ReviewState.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
        DeckWord.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
        db.session.commit()

        inserted = 0
        if cleaned:
            db.session.bulk_insert_mappings(DeckWord, cleaned)
            inserted = len(cleaned)

        p = _get_or_create_pref(current_user.id)
        if p:
            p.last_en_marker = None

        db.session.execute(text(
            "UPDATE vocab_userpref SET deck_name=:dn WHERE user_id=:uid"
        ), {"dn": deck_name, "uid": current_user.id})

        db.session.commit()

        try:
            _sse_publish(current_user.id, "stats", _calc_stats_for_user(current_user.id))
            _sse_publish(current_user.id, "deck_meta", {"deck_name": deck_name})
        except Exception:
            pass

        return jsonify({"ok": True, "inserted": inserted, "deck_name": deck_name})
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("custom_words failed: %s", e)
        return jsonify({"ok": False, "message": f"写入失败: {type(e).__name__}: {e}"}), 500

# ====== 搜索：分页搜索当前用户词库（支持 en:/zh: 前缀，支持 pool=all） ======
# ====== 搜索：分页搜索当前用户词库（支持 en:/zh:、多词 AND、前缀 ^、has_more） ======
@vocab_bp.get("/api/search_words")
@login_required
def api_search_words():
    q = (request.args.get("q") or "").strip()
    pool = (request.args.get("pool") or "easy").lower()
    if pool == "all":
        pool = "easy"
    limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    offset = max(int(request.args.get("offset", 0)), 0)

    if not q:
        return jsonify({"ok": True, "items": [], "has_more": False})

    # 字段前缀解析
    field = None
    ql = q.lower()
    if ql.startswith("en:"):
        field, q = "en", q[3:].strip()
    elif ql.startswith("zh:"):
        field, q = "zh", q[3:].strip()

    uid = current_user.id
    base = (db.session.query(DeckWord, ReviewState)
            .outerjoin(ReviewState, (ReviewState.user_id == uid) & (ReviewState.deckword_id == DeckWord.id))
            .filter(DeckWord.user_id == uid))

    # pool 过滤
    if pool == "good":
        base = base.filter(ReviewState.last_grade == 4)
    elif pool == "hard":
        base = base.filter(or_(
            and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
            and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0)
        ))

    # 字段/多词/前缀处理
    def _prefix_like(col, prefix):
        return func.lower(col).like(f"{(prefix or '').lower()}%")

    if field == "en":
        if q.startswith("^"):
            base = base.filter(_prefix_like(DeckWord.en, q[1:]))
        else:
            base = base.filter(ci_like(DeckWord.en, q))
    elif field == "zh":
        if q.startswith("^"):
            base = base.filter(_prefix_like(DeckWord.zh, q[1:]))
        else:
            base = base.filter(ci_like(DeckWord.zh, q))
    else:
        # 未指定字段：多词 AND（每个词在 en/zh 任一字段命中）
        tokens = [t for t in q.split() if t]
        for t in tokens:
            base = base.filter(or_(ci_like(DeckWord.en, t), ci_like(DeckWord.zh, t)))

    # 探针分页：limit+1
    rows = (base.order_by(func.lower(DeckWord.en).asc())
                 .limit(limit + 1).offset(offset).all())
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [{
        "id": w.id, "en": w.en, "zh": w.zh,
        "last_grade": int(st.last_grade) if st and st.last_grade is not (None) else None,
        "next_due": st.next_due.isoformat() + "Z" if st and st.next_due else None
    } for w, st in rows]

    return jsonify({"ok": True, "items": items, "has_more": has_more})

@vocab_bp.post("/api/jump_to")
@login_required
def api_jump_to():
    data = request.get_json(silent=True) or {}
    en = (data.get("en") or "").strip()
    if not en:
        return jsonify({"ok": False, "message": "en 不能为空"}), 400

    uid = current_user.id
    w = (DeckWord.query.filter_by(user_id=uid)
         .filter(ci_eq(DeckWord.en, en))
         .first())
    if not w:
        return jsonify({"ok": False, "message": "未找到该词条"}), 404

    pref = _get_or_create_pref(uid)
    pref.last_en_marker = w.en
    db.session.commit()
    try:
        _sse_publish(uid, "prefs", {"last_en_marker": pref.last_en_marker})
    except Exception:
        pass
    return jsonify({"ok": True})

# ======================= 添加/删除/重置 =======================
@vocab_bp.post("/api/add_word")
@login_required
def api_add_word():
    data = request.get_json(silent=True) or {}
    en = str(data.get("en", "")).strip()
    zh_new = str(data.get("zh", "")).strip()
    mode = str(data.get("mode") or "prepend").lower()
    if not en or not zh_new:
        return jsonify({"ok": False, "message": "en/zh 不能为空"}), 400
    try:
        exist = (DeckWord.query
                 .filter(DeckWord.user_id == current_user.id)
                 .filter(ci_eq(DeckWord.en, en))
                 .first())
        if exist:
            old = exist.zh or ""
            if mode == "replace":
                exist.zh = zh_new
            elif mode == "append":
                sep = "\n" if (old and zh_new) else ""
                exist.zh = f"{old}{sep}{zh_new}"
            else:
                sep = "\n" if (old and zh_new) else ""
                exist.zh = f"{zh_new}{sep}{old}"
        else:
            db.session.add(DeckWord(user_id=current_user.id, en=en, zh=zh_new))
        db.session.commit()
        try:
            _sse_publish(current_user.id, "stats", _calc_stats_for_user(current_user.id))
        except:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("add_word failed: %s", e)
        return jsonify({"ok": False, "message": f"添加失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.route("/api/delete_word", methods=["POST"], strict_slashes=False)
@login_required
def api_delete_word():
    data = request.get_json(silent=True) or {}
    word_id = data.get("word_id")
    en = (data.get("en") or "").strip()
    if not word_id and not en:
        return jsonify({"ok": False, "message": "word_id 或 en 必须提供其一"}), 400
    try:
        q = DeckWord.query.filter_by(user_id=current_user.id)
        if word_id:
            w = q.filter_by(id=word_id).first()
        else:
            w = q.filter(ci_eq(DeckWord.en, en)).first()
        if not w:
            return jsonify({"ok": False, "message": "未找到该词条"}), 404
        ReviewState.query.filter_by(user_id=current_user.id, deckword_id=w.id).delete(synchronize_session=False)
        deleted_en = w.en
        db.session.delete(w)
        p = _get_or_create_pref(current_user.id)
        if p and p.last_en_marker == deleted_en:
            p.last_en_marker = None
        db.session.commit()
        try:
            _sse_publish(current_user.id, "stats", _calc_stats_for_user(current_user.id))
        except:
            pass
        return jsonify({"ok": True, "deleted_id": w.id if word_id else None, "deleted_en": deleted_en})
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("delete_word failed: %s", e)
        return jsonify({"ok": False, "message": f"删除失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.post("/api/update_word")
@login_required
def api_update_word():
    data = request.get_json(silent=True) or {}
    try:
        word_id = int(data.get("word_id"))
    except Exception:
        return jsonify({"ok": False, "message": "word_id 无效"}), 400

    en = str(data.get("en") or "").strip()
    zh = str(data.get("zh") or "").strip()
    if not en or not zh:
        return jsonify({"ok": False, "message": "en/zh 不能为空"}), 400
    en = en[:256]

    try:
        w = DeckWord.query.filter_by(id=word_id, user_id=current_user.id).first()
        if not w:
            return jsonify({"ok": False, "message": "未找到该词条"}), 404

        old_en_lower = (w.en or "").lower()
        new_en_lower = en.lower()

        # 若改名，检测重名（大小写无关）
        if new_en_lower != old_en_lower:
            dup = (DeckWord.query
                   .filter(DeckWord.user_id == current_user.id)
                   .filter(ci_eq(DeckWord.en, en))
                   .filter(DeckWord.id != w.id)
                   .first())
            if dup:
                return jsonify({"ok": False, "message": "该英文已存在，无法改名为该词"}), 409

        # 更新
        w.en = en
        w.zh = zh

        # 同步顺序锚点
        p = _get_or_create_pref(current_user.id)
        if p and (p.last_en_marker or "").lower() == old_en_lower:
            p.last_en_marker = en

        db.session.commit()
        return jsonify({"ok": True, "word": {"id": w.id, "en": w.en, "zh": w.zh}})
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("update_word failed: %s", e)
        return jsonify({"ok": False, "message": f"更新失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.post("/api/reset_progress")
@login_required
def api_reset_progress():
    ReviewState.query.filter_by(user_id=current_user.id).delete(synchronize_session=False)
    p = _get_or_create_pref(current_user.id)
    if p:
        p.last_en_marker = None
        p.stats_rev = 0
    db.session.commit()
    try:
        _sse_publish(current_user.id, "stats", _calc_stats_for_user(current_user.id))
    except:
        pass
    return jsonify({"ok": True})

# ======================= 取卡 =======================
@vocab_bp.get("/api/next_card")
@login_required
def api_next_card():
    try:
        now = datetime.utcnow()
        uid = current_user.id

        req_pool = (request.args.get("pool") or "").lower().strip()
        if req_pool == "all":
            req_pool = "easy"
        if req_pool not in ("easy", "good", "hard"):
            req_pool = db.session.execute(text(
                "SELECT COALESCE(study_pool,'easy') FROM vocab_userpref WHERE user_id=:uid"
            ), {"uid": uid}).scalar() or "easy"
        pool = req_pool

        base_q = (
            db.session.query(ReviewState, DeckWord)
            .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
            .filter(ReviewState.user_id == uid)
        )

        if pool == "good":
            base_q = base_q.filter(ReviewState.last_grade == 4)
        elif pool == "hard":
            base_q = base_q.filter(
                or_(
                    and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
                    and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0),
                )
            )

        due_q = base_q if pool in ("good", "hard") else (
            db.session.query(ReviewState, DeckWord)
            .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
            .filter(ReviewState.user_id == uid)
        )
        due = due_q.filter(ReviewState.next_due <= now).order_by(ReviewState.next_due.asc()).first()
        if due:
            _st, w = due
            return jsonify({"type": "review", "word": {"id": w.id, "en": w.en, "zh": w.zh}})

        if pool == "easy":
            subq = db.session.query(ReviewState.deckword_id).filter(ReviewState.user_id == uid)
            base_new = DeckWord.query.filter(
                DeckWord.user_id == uid,
                ~DeckWord.id.in_(subq),
            )
            pref = _get_or_create_pref(uid)
            mode = (pref.sort_mode or "asc").lower()
            w = None
            if mode == "random":
                total = base_new.count()
                if total > 0:
                    offset = random.randint(0, max(0, total - 1))
                    w = base_new.order_by(DeckWord.en.asc()).offset(offset).first()
            elif mode == "desc":
                if pref.last_en_marker:
                    w = base_new.filter(DeckWord.en < pref.last_en_marker).order_by(DeckWord.en.desc()).first()
                if not w:
                    w = base_new.order_by(DeckWord.en.desc()).first()
                if w:
                    pref.last_en_marker = w.en
                    db.session.commit()
            else:  # asc
                if pref.last_en_marker:
                    w = base_new.filter(DeckWord.en > pref.last_en_marker).order_by(DeckWord.en.asc()).first()
                if not w:
                    w = base_new.order_by(DeckWord.en.asc()).first()
                if w:
                    pref.last_en_marker = w.en
                    db.session.commit()
            if w:
                return jsonify({"type": "new", "word": {"id": w.id, "en": w.en, "zh": w.zh}})

        idle_q = base_q if pool in ("good", "hard") else (
            db.session.query(ReviewState, DeckWord)
            .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
            .filter(ReviewState.user_id == uid)
        )
        next_review = idle_q.order_by(ReviewState.next_due.asc()).first()
        if next_review:
            st, w = next_review
            seconds = max(0, int((st.next_due - now).total_seconds()))
            return jsonify({"type": "idle",
                            "word": {"id": w.id, "en": w.en, "zh": w.zh},
                            "next_due_in_seconds": seconds})
        return jsonify({"type": "empty"})
    except Exception as e:
        current_app.logger.exception("next_card failed: %s", e)
        return jsonify({"ok": False, "message": f"next_card 计算失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.get("/api/next_cards")
@login_required
def api_next_cards():
    """
    批量取卡（带软时间窗）：
    - GET /api/next_cards?pool=easy&limit=10&soft_window_seconds=300&include_new=1
    - pool: easy(=All)/good/hard；传 all 视作 easy
    - limit: 返回上限（1..50）
    - soft_window_seconds: 软时间窗（0..3600），允许把 <= now+window 的卡一并返回
    - include_new: 仅在 pool=easy 时生效；用新卡补足到 limit（默认 1）
    """
    uid = current_user.id
    now = datetime.utcnow()

    req_pool = (request.args.get("pool") or "").lower().strip()
    if req_pool == "all":
        req_pool = "easy"
    if req_pool not in ("easy", "good", "hard"):
        req_pool = db.session.execute(
            text("SELECT COALESCE(study_pool,'easy') FROM vocab_userpref WHERE user_id=:uid"),
            {"uid": uid},
        ).scalar() or "easy"
    pool = req_pool

    try:
        limit = int(request.args.get("limit", 13))
    except Exception:
        limit = 13
    limit = max(1, min(55, limit))

    try:
        window = int(request.args.get("soft_window_seconds", 300))
    except Exception:
        window = 300
    window = max(0, min(3600, window))
    until = now + timedelta(seconds=window)

    include_new = request.args.get("include_new", "1") not in ("0", "false", "False")
    if pool != "easy":
        include_new = False

    items = []

    base_q = (
        db.session.query(ReviewState, DeckWord)
        .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
        .filter(ReviewState.user_id == uid)
    )
    if pool == "good":
        base_q = base_q.filter(ReviewState.last_grade == 4)
    elif pool == "hard":
        base_q = base_q.filter(
            or_(
                and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
                and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0),
            )
        )

    due_q = base_q if pool in ("good", "hard") else (
        db.session.query(ReviewState, DeckWord)
        .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
        .filter(ReviewState.user_id == uid)
    )
    due_rows = (
        due_q.filter(ReviewState.next_due <= until)
             .order_by(ReviewState.next_due.asc())
             .limit(limit)
             .all()
    )

    for st, w in due_rows:
        early = int(max(0, (st.next_due - now).total_seconds()))
        items.append({
            "type": "review",
            "word": {"id": w.id, "en": w.en, "zh": w.zh},
            "due_time": (st.next_due.replace(microsecond=0).isoformat() + "Z") if st.next_due else None,
            "early_seconds": early,
        })

    remain = limit - len(items)
    if include_new and remain > 0:
        subq = db.session.query(ReviewState.deckword_id).filter(ReviewState.user_id == uid)
        base_new = DeckWord.query.filter(DeckWord.user_id == uid, ~DeckWord.id.in_(subq))

        pref = _get_or_create_pref(uid)
        mode = (pref.sort_mode or "asc").lower()
        picked = []

        if mode == "random":
            total_new = base_new.count()
            tried = set()
            while remain > 0 and total_new > 0 and len(tried) < min(total_new, remain * 3):
                offset = random.randint(0, max(0, total_new - 1))
                if offset in tried:
                    continue
                tried.add(offset)
                w = base_new.order_by(DeckWord.en.asc()).offset(offset).first()
                if w and w.id not in {x.id for x in picked}:
                    picked.append(w)
                    remain -= 1

        elif mode == "desc":
            marker = (pref.last_en_marker or "")
            q1 = base_new.filter(DeckWord.en < marker) if marker else base_new
            part1 = q1.order_by(DeckWord.en.desc()).limit(remain).all()
            picked.extend(part1)
            if len(picked) < limit and (not marker or base_new.count() > len(part1)):
                need = limit - len(picked)
                part2 = base_new.order_by(DeckWord.en.desc()).limit(need).all()
                existed = {w.id for w in picked}
                part2 = [w for w in part2 if w.id not in existed]
                picked.extend(part2)
            if picked:
                pref.last_en_marker = picked[-1].en
                db.session.commit()

        else:  # "asc"
            marker = (pref.last_en_marker or "")
            q1 = base_new.filter(DeckWord.en > marker) if marker else base_new
            part1 = q1.order_by(DeckWord.en.asc()).limit(remain).all()
            picked.extend(part1)
            if len(picked) < limit and (not marker or base_new.count() > len(part1)):
                need = limit - len(picked)
                part2 = base_new.order_by(DeckWord.en.asc()).limit(need).all()
                existed = {w.id for w in picked}
                part2 = [w for w in part2 if w.id not in existed]
                picked.extend(part2)
            if picked:
                pref.last_en_marker = picked[-1].en
                db.session.commit()

        for w in picked[:max(0, limit - len(items))]:
            items.append({
                "type": "new",
                "word": {"id": w.id, "en": w.en, "zh": w.zh},
                "due_time": None,
                "early_seconds": 0,
            })

    return jsonify({"ok": True, "items": items, "window_seconds": window})

# ======================= 打分（含：提前补偿 + 到期聚合） =======================
def _ensure_reviewstate_srs_columns():
    """Add the additional SM-2 review fields when using an older local database."""
    _ensure_columns("vocab_reviewstate", {
        "consec_easy": "INTEGER NOT NULL DEFAULT 0",
        "hard_streak": "INTEGER NOT NULL DEFAULT 0",
        "last_interval_hours": "FLOAT NULL",
    })
@vocab_bp.post("/api/defer")
@login_required
def api_defer():
    """
    延后复现：将当前词的复现时间推迟到指定时长后（4周/3个月/1年）
    仍走现有的"到期聚合 + 提前补偿"逻辑，保持统计一致性
    """
    _ensure_reviewstate_srs_columns()

    data = request.get_json(silent=True) or {}
    try:
        word_id = int(data.get("word_id"))
    except Exception:
        return jsonify({"ok": False, "message": "word_id 无效"}), 400

    defer_type = str(data.get("defer_type") or "").lower()
    if defer_type not in ("4weeks", "3months", "1year", "short_random", "long_random"):
        return jsonify({"ok": False, "message": "defer_type 仅支持 4weeks/3months/1year/short_random/long_random"}), 400

    # 基础对象
    w = DeckWord.query.filter_by(id=word_id, user_id=current_user.id).first()
    if not w:
        return jsonify({"ok": False, "message": "未找到该词条"}), 404

    now = datetime.utcnow()
    st = ReviewState.query.filter_by(user_id=current_user.id, deckword_id=w.id).first()
    if not st:
        st = ReviewState(user_id=current_user.id, deckword_id=w.id)
        db.session.add(st)
        # 初始化默认值
        try:
            st.consec_easy = 0
            st.hard_streak = 0
            st.last_interval_hours = None
        except Exception:
            pass

    # 计算延后时长（转换为小时）
    defer_hours_map = {
        "4weeks": 24 * 7 * 4,      # 4周 = 672小时
        "3months": 24 * 30 * 3,     # 3个月 = 2160小时（按30天/月计算）
        "1year": 24 * 365          # 1年 = 8760小时
    }
    
    if defer_type == "short_random":
        # 短期随机：1-14天之间随机分配
        import random
        random_days = random.randint(1, 14)
        defer_hours = 24 * random_days
    elif defer_type == "long_random":
        # 中期随机：13-55天之间随机分配
        import random
        random_days = random.randint(13, 55)
        defer_hours = 24 * random_days
    else:
        defer_hours = defer_hours_map[defer_type]

    # 设置高等级和连续easy次数，表示这是一个被用户主动延后的词
    st.last_grade = 5  # Very Easy
    try:
        st.consec_easy = max(getattr(st, "consec_easy", 0) + 5, 10)  # 大幅增加连续easy次数
        st.hard_streak = 0
        st.last_interval_hours = float(defer_hours)
    except Exception:
        pass

    # 计算提前补偿（如果当前有到期时间的话）
    early_seconds = 0
    try:
        if st.next_due and isinstance(st.next_due, datetime):
            early_seconds = max(0, int((st.next_due - now).total_seconds()))
    except Exception:
        early_seconds = 0

    # 应用现有的"提前补偿 + 到期聚合"逻辑
    raw_next_due = now + timedelta(hours=defer_hours)
    compensated_due = _apply_early_compensation(now, raw_next_due, early_seconds)
    final_due = _bucketize_due(now, compensated_due)
    
    st.next_due = final_due

    # 持久化
    db.session.commit()
    
    # 计算下次复现的秒数
    next_in_seconds = int((final_due - now).total_seconds())
    
    # 返回统计信息
    stats = _calc_stats_for_user(current_user.id)
    try:
        _sse_publish(current_user.id, "stats", stats)
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "defer_type": defer_type,
        "defer_hours": defer_hours,
        "next_due": final_due.replace(microsecond=0).isoformat() + "Z",
        "next_in_seconds": max(0, next_in_seconds),
        "stats": stats
    })

@vocab_bp.route("/api/review", methods=["POST"], strict_slashes=False)
@login_required
def api_review():
    """
    接收 { word_id, grade } 并更新 ReviewState：
    - 先根据 grade 计算基础间隔（delta）
    - 如果“这次学习发生在原计划 next_due 之前”，对 delta 做“提前补偿”
    - 对最终 next_due 做“到期聚合”（分钟/5分钟桶）
    - 返回最新统计 stats
    """
    data = request.get_json(silent=True) or {}
    try:
        word_id = int(data.get("word_id"))
    except Exception:
        return jsonify({"ok": False, "message": "word_id 无效"}), 400

    try:
        grade = int(data.get("grade", 0))
    except Exception:
        grade = 0
    if grade not in (1, 2, 3, 4, 5):
        return jsonify({"ok": False, "message": "grade 取值需在 1~5"}), 400

    w = DeckWord.query.filter_by(id=word_id, user_id=current_user.id).first()
    if not w:
        return jsonify({"ok": False, "message": "未找到该词条"}), 404

    now = datetime.utcnow()

    st = ReviewState.query.filter_by(user_id=current_user.id, deckword_id=w.id).first()
    if not st:
        st = ReviewState(user_id=current_user.id, deckword_id=w.id)
        db.session.add(st)

    st.last_grade = grade
    if grade <= 2:
        st.wrong_count = (st.wrong_count or 0) + 1

    if grade == 5:
        delta = timedelta(days=3)
    elif grade == 4:
        delta = timedelta(days=1)
    elif grade == 3:
        delta = timedelta(hours=8)
    elif grade == 2:
        delta = timedelta(hours=2)
    else:
        delta = timedelta(minutes=30)

    early_seconds = 0
    try:
        if st.next_due and isinstance(st.next_due, datetime):
            early_seconds = max(0, int((st.next_due - now).total_seconds()))
    except Exception:
        early_seconds = 0

    raw_next_due = now + delta
    compensated_due = _apply_early_compensation(now, raw_next_due, early_seconds)
    final_due = _bucketize_due(now, compensated_due)
    st.next_due = final_due

    db.session.commit()
    stats = _calc_stats_for_user(current_user.id)
    try:
        _sse_publish(current_user.id, "stats", stats)
    except Exception:
        pass
    return jsonify({"ok": True, "stats": stats})

@vocab_bp.post("/api/rate")
@login_required
def api_rate():
    """
    新评分接口：接收 { word_id, ui, rt_total_ms, used_reveal, pre_reveal_ms, def_dwell_ms, def_len_chars, device }
    - 把 UI 的 hard/good/easy 映射为 1..5 档（again/hard/good/easy/very easy）
    - 依据上次间隔（last_interval_hours）计算下一次间隔，保存在 ReviewState
    - 应用“提前补偿 + 到期聚合”
    - 返回 next_in_seconds：基于最终到期时间计算的“距离下次复现”的秒数
    """
    _ensure_reviewstate_srs_columns()

    data = request.get_json(silent=True) or {}
    try:
        word_id = int(data.get("word_id"))
    except Exception:
        return jsonify({"ok": False, "message": "word_id 无效"}), 400

    ui = str(data.get("ui") or "").lower()
    if ui not in ("hard", "good", "easy"):
        return jsonify({"ok": False, "message": "ui 仅支持 hard/good/easy"}), 400

    # 行为 & 设备
    rt_total_ms   = int(data.get("rt_total_ms") or 0)
    used_reveal   = bool(data.get("used_reveal") or False)
    pre_reveal_ms = int(data.get("pre_reveal_ms") or 0)
    def_dwell_ms  = int(data.get("def_dwell_ms") or 0)
    def_len_chars = int(data.get("def_len_chars") or 0)
    device        = str(data.get("device") or "desktop").lower()

    # 基础对象
    w = DeckWord.query.filter_by(id=word_id, user_id=current_user.id).first()
    if not w:
        return jsonify({"ok": False, "message": "未找到该词条"}), 404

    now = datetime.utcnow()
    st = ReviewState.query.filter_by(user_id=current_user.id, deckword_id=w.id).first()
    if not st:
        st = ReviewState(user_id=current_user.id, deckword_id=w.id)
        db.session.add(st)
        # 初始三列保证存在（默认 0/NULL）
        try:
            st.consec_easy = 0
            st.hard_streak = 0
            st.last_interval_hours = None
        except Exception:
            pass  # 列可能尚未建好，但 _ensure 已处理

    # 读取 streak / last_interval
    consec_easy = getattr(st, "consec_easy", 0) or 0
    hard_streak = getattr(st, "hard_streak", 0) or 0
    last_interval_h = getattr(st, "last_interval_hours", None)

    # 3→5 档映射
    grade = map_ui_to_grade(
        ui=ui,
        rt_total_ms=rt_total_ms,
        used_reveal=used_reveal,
        pre_reveal_ms=pre_reveal_ms,
        def_dwell_ms=def_dwell_ms,
        def_len_chars=def_len_chars,
        consec_easy=consec_easy,
        hard_streak=hard_streak,
        last_interval_h=last_interval_h,
        device=device
    )
    st.last_grade = grade

    # streak 更新
    if grade in (4, 5):
        consec_easy += 1
    else:
        consec_easy = 0
    if grade in (1, 2):
        hard_streak += 1
    else:
        hard_streak = 0
    try:
        st.consec_easy = consec_easy
        st.hard_streak = hard_streak
    except Exception:
        pass

    # 计算下一次间隔（小时）
    nxt_h = compute_next_interval(last_interval_h, grade)

    # 提前补偿（学习提前触发的扣减）
    early_seconds = 0
    try:
        if st.next_due and isinstance(st.next_due, datetime):
            early_seconds = max(0, int((st.next_due - now).total_seconds()))
    except Exception:
        early_seconds = 0

    # 优化版时间计算流程：减少重复计算，一次性完成
    raw_next_due = now + timedelta(hours=nxt_h)
    compensated_due = _apply_early_compensation(now, raw_next_due, early_seconds)
    final_due = _bucketize_due(now, compensated_due)
    
    # 一次性计算并设置所有时间相关字段
    st.next_due = final_due
    next_in_seconds = int((final_due - now).total_seconds())
    
    try:
        st.last_interval_hours = float(nxt_h)
    except Exception:
        pass

    # 持久化与统计
    db.session.commit()
    stats = _calc_stats_for_user(current_user.id)
    try:
        _sse_publish(current_user.id, "stats", stats)
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "grade": int(grade),
        "next_interval_hours": float(nxt_h),
        "next_due": final_due.replace(microsecond=0).isoformat() + "Z",
        "next_in_seconds": max(0, next_in_seconds),
        "stats": stats
    })


# ======================= 错词导入导出 =======================
@vocab_bp.get("/api/export_wrong")
@login_required
def api_export_wrong():
    include_good = str(request.args.get("include_good", "")).lower() in ("1", "true", "yes", "on")
    base_q = (
        db.session.query(ReviewState, DeckWord)
        .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
        .filter(ReviewState.user_id == current_user.id)
    )
    cond_hard = or_(
        ReviewState.wrong_count > 0,
        and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
    )
    cond = cond_hard if not include_good else or_(cond_hard, ReviewState.last_grade == 4)
    states = base_q.filter(cond).all()
    out = [{"en": w.en, "zh": w.zh} for _st, w in states]
    buf = BytesIO(json.dumps(out, ensure_ascii=False, indent=2).encode("utf-8"))
    buf.seek(0)
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=f"wrong_words_{current_user.username}.json")

@vocab_bp.post("/api/import_wrong")
@login_required
def api_import_wrong():
    arr = request.get_json(silent=True) or []
    if not isinstance(arr, list):
        return jsonify({"ok": False, "message": "格式错误，应为数组"}), 400
    try:
        for item in arr:
            if not isinstance(item, dict):
                continue
            en = str(item.get("en") or "").strip()
            zh = str(item.get("zh") or "").strip()
            if not en or not zh:
                continue
            dw = DeckWord.query.filter_by(user_id=current_user.id, en=en).first()
            if not dw:
                dw = DeckWord(user_id=current_user.id, en=en, zh=zh)
                db.session.add(dw)
                db.session.flush()
            st = ReviewState.query.filter_by(user_id=current_user.id, deckword_id=dw.id).first()
            if not st:
                st = ReviewState(user_id=current_user.id, deckword_id=dw.id)
                db.session.add(st)
            st.wrong_count = (st.wrong_count or 0) + 1
        db.session.commit()
        try:
            _sse_publish(current_user.id, "stats", _calc_stats_for_user(current_user.id))
        except:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "message": f"导入失败: {type(e).__name__}: {e}"}), 500

@vocab_bp.post("/api/import_ranking_complete")
@login_required
def api_import_ranking_complete():
    """
    导入排行榜完整数据，包括点击统计和复习状态
    支持完整的学习数据恢复
    """
    try:
        data = request.get_json(silent=True) or {}
        words = data.get("words", [])
        source_info = data.get("source_info", {})
        
        if not isinstance(words, list):
            return jsonify({"ok": False, "message": "words字段必须是数组"}), 400
        
        import_stats = {
            "total_processed": 0,
            "words_created": 0,
            "words_updated": 0,
            "click_stats_created": 0,
            "click_stats_updated": 0,
            "review_states_created": 0,
            "review_states_updated": 0,
            "errors": []
        }
        
        for item in words:
            if not isinstance(item, dict):
                continue
                
            en = str(item.get("en") or "").strip()
            zh = str(item.get("zh") or "").strip()
            if not en or not zh:
                continue
                
            try:
                import_stats["total_processed"] += 1
                
                # 1. 处理词汇数据
                dw = DeckWord.query.filter_by(user_id=current_user.id, en=en).first()
                if not dw:
                    dw = DeckWord(user_id=current_user.id, en=en, zh=zh)
                    db.session.add(dw)
                    db.session.flush()  # 获取ID
                    import_stats["words_created"] += 1
                else:
                    # 更新中文释义（如果导入的更完整）
                    if len(zh) > len(dw.zh or ""):
                        dw.zh = zh
                    import_stats["words_updated"] += 1
                
                # 2. 处理点击统计数据
                click_count = item.get("click_count")
                first_click_time = item.get("first_click_time")
                last_click_time = item.get("last_click_time")
                
                if click_count and click_count > 0:
                    # 导入WordClickStat数据
                    from .models import WordClickStat
                    
                    click_stat = WordClickStat.query.filter_by(
                        user_id=current_user.id, 
                        deckword_id=dw.id
                    ).first()
                    
                    if not click_stat:
                        click_stat = WordClickStat(
                            user_id=current_user.id,
                            deckword_id=dw.id,
                            click_count=click_count,
                            first_click_time=_parse_time_string(first_click_time) if first_click_time else now_beijing(),
                            last_click_time=_parse_time_string(last_click_time) if last_click_time else now_beijing()
                        )
                        db.session.add(click_stat)
                        import_stats["click_stats_created"] += 1
                    else:
                        # 合并点击统计：保留更大的计数和更早/更晚的时间
                        if click_count > click_stat.click_count:
                            click_stat.click_count = click_count
                        
                        if first_click_time:
                            parsed_first = _parse_time_string(first_click_time)
                            if not click_stat.first_click_time or parsed_first < click_stat.first_click_time:
                                click_stat.first_click_time = parsed_first
                                
                        if last_click_time:
                            parsed_last = _parse_time_string(last_click_time)
                            if not click_stat.last_click_time or parsed_last > click_stat.last_click_time:
                                click_stat.last_click_time = parsed_last
                                
                        import_stats["click_stats_updated"] += 1
                
                # 3. 处理复习状态数据
                review_state_data = item.get("review_state")
                if review_state_data and isinstance(review_state_data, dict):
                    review_state = ReviewState.query.filter_by(
                        user_id=current_user.id, 
                        deckword_id=dw.id
                    ).first()
                    
                    if not review_state:
                        review_state = ReviewState(
                            user_id=current_user.id,
                            deckword_id=dw.id
                        )
                        db.session.add(review_state)
                        import_stats["review_states_created"] += 1
                    else:
                        import_stats["review_states_updated"] += 1
                    
                    # 设置复习状态字段
                    if review_state_data.get("last_grade") is not None:
                        review_state.last_grade = int(review_state_data["last_grade"])
                    
                    if review_state_data.get("wrong_count") is not None:
                        # 累加错误次数而不是覆盖
                        review_state.wrong_count = (review_state.wrong_count or 0) + int(review_state_data["wrong_count"])
                    
                    # 设置SRS增强字段（如果存在）
                    _ensure_reviewstate_srs_columns()  # 确保列存在
                    
                    try:
                        if review_state_data.get("last_interval_hours") is not None:
                            review_state.last_interval_hours = float(review_state_data["last_interval_hours"])
                        if review_state_data.get("hard_streak") is not None:
                            review_state.hard_streak = int(review_state_data["hard_streak"])
                        if review_state_data.get("consec_easy") is not None:
                            review_state.consec_easy = int(review_state_data["consec_easy"])
                    except Exception as e:
                        # SRS字段导入失败不影响主流程
                        import_stats["errors"].append(f"导入SRS数据失败 {en}: {e}")
                        
                else:
                    # 没有复习状态数据，但有点击统计，说明是错词，创建基本的复习状态
                    if click_count and click_count > 0:
                        review_state = ReviewState.query.filter_by(
                            user_id=current_user.id, 
                            deckword_id=dw.id
                        ).first()
                        
                        if not review_state:
                            review_state = ReviewState(
                                user_id=current_user.id,
                                deckword_id=dw.id,
                                wrong_count=1  # 默认标记为错词
                            )
                            db.session.add(review_state)
                            import_stats["review_states_created"] += 1
                            
            except Exception as e:
                import_stats["errors"].append(f"处理词条 {en} 时出错: {e}")
                continue
        
        db.session.commit()
        
        # 推送统计更新
        try:
            _sse_publish(current_user.id, "stats", _calc_stats_for_user(current_user.id))
        except:
            pass
        
        return jsonify({
            "ok": True,
            "message": "排行榜完整数据导入成功",
            "stats": import_stats,
            "source_info": source_info
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("导入排行榜完整数据失败: %s", e)
        return jsonify({
            "ok": False, 
            "message": f"导入排行榜数据失败: {type(e).__name__}: {e}"
        }), 500

def _parse_time_string(time_str):
    """解析时间字符串，支持多种格式"""
    if not time_str:
        return now_beijing()
    
    try:
        # 尝试解析 "YYYY-MM-DD HH:MM" 格式
        if len(time_str) == 16 and " " in time_str:
            return datetime.strptime(time_str, "%Y-%m-%d %H:%M").replace(tzinfo=BEIJING_TZ)
        
        # 尝试解析 ISO 格式
        from dateutil import parser
        parsed = parser.parse(time_str)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=BEIJING_TZ)
        return parsed.astimezone(BEIJING_TZ)
        
    except Exception:
        # 解析失败，返回当前时间
        return now_beijing()

# ======================= 时间分布管理API =======================
from collections import defaultdict
from typing import List, Dict

@vocab_bp.get("/api/time_distribution_analysis")
@login_required
def api_time_distribution_analysis():
    """
    分析当日学习时间分布
    GET /api/time_distribution_analysis?date=2025-08-25
    """
    try:
        # 获取查询日期
        date_str = request.args.get('date')
        if date_str:
            target_date = datetime.strptime(date_str, '%Y-%m-%d')
        else:
            target_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        uid = current_user.id
        
        # 定义学习时间范围（5:00-23:00）
        start_time = target_date.replace(hour=5, minute=0, second=0, microsecond=0)
        end_time = target_date.replace(hour=23, minute=0, second=0, microsecond=0)
        
        # 查询当日学习时间分布
        review_times = db.session.query(ReviewState.next_due).filter(
            ReviewState.user_id == uid,
            ReviewState.next_due >= start_time,
            ReviewState.next_due <= end_time
        ).all()
        
        times_list = [rt.next_due for rt in review_times if rt.next_due]
        
        # 分析时间分布
        analysis_result = _analyze_time_distribution(times_list, start_time, end_time)
        
        return jsonify({
            "ok": True,
            "date": target_date.strftime('%Y-%m-%d'),
            "total_words": len(times_list),
            "study_time_range": {
                "start": "05:00",
                "end": "23:00"
            },
            **analysis_result
        })
        
    except Exception as e:
        current_app.logger.exception("time_distribution_analysis failed: %s", e)
        return jsonify({
            "ok": False, 
            "message": f"时间分布分析失败: {type(e).__name__}: {e}"
        }), 500

@vocab_bp.post("/api/redistribute_study_times")
@login_required
def api_redistribute_study_times():
    """
    重新分配学习时间，将集中的时间点分散
    POST /api/redistribute_study_times
    {
        "date": "2025-08-25",  // 可选，默认为今天
        "word_ids": [1,2,3],   // 可选，指定单词ID列表
        "mode": "smart"        // 分配模式：random(随机) 或 smart(智能分散)
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        uid = current_user.id
        
        # 获取参数
        date_str = data.get('date')
        if date_str:
            target_date = datetime.strptime(date_str, '%Y-%m-%d')
        else:
            target_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        word_ids = data.get('word_ids', [])
        mode = data.get('mode', 'smart')  # smart 或 random
        
        # 定义学习时间范围
        start_time = target_date.replace(hour=5, minute=0, second=0, microsecond=0)
        end_time = target_date.replace(hour=23, minute=0, second=0, microsecond=0)
        
        # 如果没有指定word_ids，查找当日需要重新分配的单词
        if not word_ids:
            word_ids = _find_congested_words(uid, start_time, end_time)
        
        if not word_ids:
            return jsonify({
                "ok": True,
                "message": "没有需要重新分配的单词",
                "redistributed_count": 0
            })
        
        # 执行时间重新分配
        redistribution_result = _redistribute_words_times(
            uid, word_ids, start_time, end_time, mode
        )
        
        return jsonify({
            "ok": True,
            "date": target_date.strftime('%Y-%m-%d'),
            "mode": mode,
            "redistributed_count": redistribution_result['count'],
            "time_range": {
                "start": "05:00",
                "end": "23:00"
            },
            "redistribution_log": redistribution_result['log'][:20]  # 最多返回20条日志
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("redistribute_study_times failed: %s", e)
        return jsonify({
            "ok": False,
            "message": f"时间重新分配失败: {type(e).__name__}: {e}"
        }), 500

@vocab_bp.get("/api/daily_schedule_summary")
@login_required
def api_daily_schedule_summary():
    """
    获取每日学习时间安排摘要
    GET /api/daily_schedule_summary?date=2025-08-25
    """
    try:
        date_str = request.args.get('date')
        if date_str:
            target_date = datetime.strptime(date_str, '%Y-%m-%d')
        else:
            target_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        uid = current_user.id
        start_time = target_date.replace(hour=5, minute=0, second=0, microsecond=0)
        end_time = target_date.replace(hour=23, minute=0, second=0, microsecond=0)
        
        # 统计当日学习安排
        total_scheduled = db.session.query(func.count(ReviewState.id)).filter(
            ReviewState.user_id == uid,
            ReviewState.next_due >= start_time,
            ReviewState.next_due <= end_time
        ).scalar() or 0
        
        # 按时段分组统计
        morning_count = db.session.query(func.count(ReviewState.id)).filter(
            ReviewState.user_id == uid,
            ReviewState.next_due >= start_time.replace(hour=5),
            ReviewState.next_due < start_time.replace(hour=10)
        ).scalar() or 0
        
        afternoon_count = db.session.query(func.count(ReviewState.id)).filter(
            ReviewState.user_id == uid,
            ReviewState.next_due >= start_time.replace(hour=10),
            ReviewState.next_due < start_time.replace(hour=16)
        ).scalar() or 0
        
        evening_count = db.session.query(func.count(ReviewState.id)).filter(
            ReviewState.user_id == uid,
            ReviewState.next_due >= start_time.replace(hour=16),
            ReviewState.next_due <= end_time
        ).scalar() or 0
        
        return jsonify({
            "ok": True,
            "date": target_date.strftime('%Y-%m-%d'),
            "total_scheduled": total_scheduled,
            "time_distribution": {
                "morning": {"count": morning_count, "range": "05:00-10:00"},
                "afternoon": {"count": afternoon_count, "range": "10:00-16:00"}, 
                "evening": {"count": evening_count, "range": "16:00-23:00"}
            },
            "study_efficiency": {
                "words_per_hour": round(total_scheduled / 18, 1) if total_scheduled > 0 else 0,
                "distribution_balance": _calculate_balance_score([morning_count, afternoon_count, evening_count])
            }
        })
        
    except Exception as e:
        current_app.logger.exception("daily_schedule_summary failed: %s", e)
        return jsonify({
            "ok": False,
            "message": f"每日安排摘要获取失败: {type(e).__name__}: {e}"
        }), 500

# ======================= 时间分布分析辅助函数 =======================

def _analyze_time_distribution(times_list: List[datetime], start_time: datetime, end_time: datetime) -> Dict:
    """分析时间分布"""
    if not times_list:
        return {
            "hourly_distribution": {},
            "time_slots": {"morning": 0, "afternoon": 0, "evening": 0},
            "congestion_points": [],
            "distribution_quality": "excellent"
        }
    
    # 按小时分组统计
    hourly_count = defaultdict(int)
    for time_point in times_list:
        hourly_count[time_point.hour] += 1
    
    # 时间段分析
    time_slots = {"morning": 0, "afternoon": 0, "evening": 0}
    for time_point in times_list:
        hour = time_point.hour
        if 5 <= hour < 10:
            time_slots['morning'] += 1
        elif 10 <= hour < 16:
            time_slots['afternoon'] += 1
        elif 16 <= hour <= 23:
            time_slots['evening'] += 1
    
    # 拥堵点分析（按5分钟间隔）
    time_buckets = defaultdict(int)
    for time_point in times_list:
        bucket_minute = (time_point.minute // 5) * 5
        bucket_time = time_point.replace(minute=bucket_minute, second=0, microsecond=0)
        time_buckets[bucket_time] += 1
    
    # 找出拥堵点
    if time_buckets:
        avg_count = len(times_list) / len(time_buckets)
        congestion_threshold = max(avg_count * 2, 3)
        
        congestion_points = []
        for bucket_time, count in time_buckets.items():
            if count >= congestion_threshold:
                severity = 'high' if count >= congestion_threshold * 1.5 else 'medium'
                congestion_points.append({
                    'time': bucket_time.strftime('%H:%M'),
                    'count': count,
                    'severity': severity
                })
        
        congestion_points.sort(key=lambda x: x['count'], reverse=True)
    else:
        congestion_points = []
    
    # 评估分布质量
    distribution_quality = _evaluate_distribution_quality(
        len(times_list), len(congestion_points), hourly_count
    )
    
    return {
        "hourly_distribution": dict(hourly_count),
        "time_slots": time_slots,
        "congestion_points": congestion_points[:10],
        "distribution_quality": distribution_quality
    }

def _evaluate_distribution_quality(total_words: int, congestion_count: int, hourly_dist: Dict) -> str:
    """评估时间分布质量"""
    if total_words == 0:
        return "no_data"
    
    if hourly_dist:
        counts = list(hourly_dist.values())
        max_count = max(counts)
        avg_count = sum(counts) / len(counts)
        uniformity_ratio = avg_count / max_count if max_count > 0 else 1
    else:
        uniformity_ratio = 1
    
    congestion_ratio = congestion_count / max(total_words / 10, 1)
    
    if uniformity_ratio > 0.7 and congestion_ratio < 0.3:
        return "excellent"
    elif uniformity_ratio > 0.5 and congestion_ratio < 0.5:
        return "good"
    elif uniformity_ratio > 0.3 and congestion_ratio < 0.7:
        return "fair"
    else:
        return "poor"

def _find_congested_words(uid: int, start_time: datetime, end_time: datetime) -> List[int]:
    """找出时间集中的单词ID"""
    review_states = db.session.query(ReviewState).filter(
        ReviewState.user_id == uid,
        ReviewState.next_due >= start_time,
        ReviewState.next_due <= end_time
    ).all()
    
    time_buckets = defaultdict(list)
    for rs in review_states:
        if rs.next_due:
            bucket_minute = (rs.next_due.minute // 5) * 5
            bucket_time = rs.next_due.replace(minute=bucket_minute, second=0, microsecond=0)
            time_buckets[bucket_time].append(rs.deckword_id)
    
    if not time_buckets:
        return []
    
    avg_count = len(review_states) / len(time_buckets)
    congestion_threshold = max(avg_count * 2, 3)
    
    congested_word_ids = []
    for bucket_time, word_ids in time_buckets.items():
        if len(word_ids) >= congestion_threshold:
            sample_size = max(len(word_ids) // 2, 1)
            congested_word_ids.extend(random.sample(word_ids, sample_size))
    
    return congested_word_ids

def _redistribute_words_times(uid: int, word_ids: List[int], start_time: datetime, 
                            end_time: datetime, mode: str = 'smart') -> Dict:
    """重新分配单词学习时间"""
    redistributed_count = 0
    redistribution_log = []
    
    existing_times = []
    if mode == 'smart':
        existing_review_states = db.session.query(ReviewState.next_due).filter(
            ReviewState.user_id == uid,
            ReviewState.next_due >= start_time,
            ReviewState.next_due <= end_time,
            ~ReviewState.deckword_id.in_(word_ids)
        ).all()
        existing_times = [rt.next_due for rt in existing_review_states if rt.next_due]
    
    for word_id in word_ids:
        try:
            if mode == 'smart':
                new_time = _generate_smart_time(start_time, end_time, existing_times)
                existing_times.append(new_time)
            else:
                new_time = _generate_random_time(start_time, end_time)
            
            # 应用现有的bucketize逻辑
            new_time = _bucketize_due(datetime.utcnow(), new_time)
            
            review_state = ReviewState.query.filter_by(
                user_id=uid, 
                deckword_id=word_id
            ).first()
            
            if review_state:
                old_time = review_state.next_due
                review_state.next_due = new_time
                
                redistribution_log.append({
                    'word_id': word_id,
                    'old_time': old_time.strftime('%H:%M:%S') if old_time else None,
                    'new_time': new_time.strftime('%H:%M:%S'),
                    'date': new_time.strftime('%Y-%m-%d')
                })
                
                redistributed_count += 1
        
        except Exception as e:
            current_app.logger.warning(f"Failed to redistribute word {word_id}: {e}")
            continue
    
    db.session.commit()
    
    return {
        'count': redistributed_count,
        'log': redistribution_log
    }

def _generate_random_time(start_time: datetime, end_time: datetime) -> datetime:
    """生成随机时间"""
    total_seconds = int((end_time - start_time).total_seconds())
    random_seconds = random.randint(0, total_seconds)
    return start_time + timedelta(seconds=random_seconds)

def _generate_smart_time(start_time: datetime, end_time: datetime, 
                        existing_times: List[datetime]) -> datetime:
    """生成智能分散的时间"""
    max_attempts = 50
    min_interval_minutes = 5
    
    for attempt in range(max_attempts):
        candidate_time = _generate_random_time(start_time, end_time)
        
        if existing_times:
            min_gap = min(
                abs((candidate_time - existing).total_seconds()) / 60
                for existing in existing_times
            )
            
            if min_gap >= min_interval_minutes:
                return candidate_time
        else:
            return candidate_time
    
    return _generate_random_time(start_time, end_time)

def _calculate_balance_score(counts: List[int]) -> str:
    """计算分布平衡度评分"""
    if not counts or sum(counts) == 0:
        return "no_data"
    
    mean = sum(counts) / len(counts)
    if mean == 0:
        return "no_data"
    
    variance = sum((x - mean) ** 2 for x in counts) / len(counts)
    cv = (variance ** 0.5) / mean
    
    if cv < 0.3:
        return "excellent"
    elif cv < 0.6:
        return "good"
    elif cv < 1.0:
        return "fair"
    else:
        return "poor"



@vocab_bp.get("/api/top_clicked_words")
@login_required
def api_top_clicked_words():
    """获取用户点击数最多的单词（支持分页）"""
    try:
        uid = current_user.id
        
        # 获取分页参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 55, type=int)
        
        # 限制每页数量
        per_page = min(per_page, 100)  # 最大100个
        offset = (page - 1) * per_page
        
        # 先获取总数
        total_query = (db.session.query(WordClickStat)
                      .join(DeckWord, WordClickStat.deckword_id == DeckWord.id)
                      .filter(WordClickStat.user_id == uid)
                      .filter(DeckWord.user_id == uid))
        total_count = total_query.count()
        
        # 查询点击统计数据，按点击次数降序排列，支持分页
        top_stats = (db.session.query(WordClickStat, DeckWord)
                    .join(DeckWord, WordClickStat.deckword_id == DeckWord.id)
                    .filter(WordClickStat.user_id == uid)
                    .filter(DeckWord.user_id == uid)
                    .order_by(WordClickStat.click_count.desc(), WordClickStat.last_click_time.desc())
                    .offset(offset)
                    .limit(per_page)
                    .all())
        
        result = []
        for stat, word in top_stats:
            # 计算距离首次点击的时间（修复时区问题）
            if stat.first_click_time:
                try:
                    # 如果数据库中的时间没有时区信息，假设它是北京时间
                    if stat.first_click_time.tzinfo is None:
                        # 将naive datetime当作北京时间
                        db_time = stat.first_click_time.replace(tzinfo=BEIJING_TZ)
                    else:
                        db_time = stat.first_click_time
                    
                    now = now_beijing()
                    time_diff = now - db_time
                    
                    time_ago = format_time_diff(time_diff.total_seconds())
                except Exception as e:
                    current_app.logger.warning(f"时间计算出错: {e}")
                    time_ago = "时间计算错误"
            else:
                time_ago = "未知"
            
            result.append({
                "word_id": word.id,
                "en": word.en,
                "zh": word.zh[:100] + "..." if len(word.zh or "") > 100 else (word.zh or ""),  # 限制中文长度
                "click_count": stat.click_count,
                "last_click_time": stat.last_click_time.strftime("%Y-%m-%d %H:%M") if stat.last_click_time else None,
                "first_click_time": stat.first_click_time.strftime("%Y-%m-%d %H:%M") if stat.first_click_time else None,
                "time_ago": time_ago
            })
        
        return jsonify({
            "ok": True,
            "total_words": total_count,
            "current_page": page,
            "per_page": per_page,
            "total_pages": (total_count + per_page - 1) // per_page,  # 向上取整
            "has_next": page * per_page < total_count,
            "has_prev": page > 1,
            "words": result
        })
        
    except Exception as e:
        current_app.logger.exception("top_clicked_words failed: %s", e)
        return jsonify({
            "ok": False,
            "message": f"获取统计失败: {type(e).__name__}: {e}"
        }), 500


# ======================= 单词点击统计 =======================



@vocab_bp.get("/api/word_click_stats")
@login_required
def get_word_click_stats():
    """获取用户的单词点击统计"""
    try:
        stats = db.session.query(WordClickStat, DeckWord.id).join(
            DeckWord, WordClickStat.deckword_id == DeckWord.id
        ).filter(
            WordClickStat.user_id == current_user.id
        ).all()
        
        result = {}
        for stat, word_id in stats:
            result[str(word_id)] = {
                "count": stat.click_count,
                "lastClickTime": int(stat.last_click_time.timestamp() * 1000),
                "firstClickTime": int(stat.first_click_time.timestamp() * 1000)
            }
        
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"获取点击统计失败: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@vocab_bp.route("/api/word_click_stats/<int:word_id>", methods=["GET", "POST"])
@login_required  
def word_click_stats(word_id):
    """获取或记录单词点击统计"""
    try:
        # 验证单词是否属于当前用户
        word = DeckWord.query.filter_by(
            id=word_id, 
            user_id=current_user.id
        ).first()
        
        if not word:
            current_app.logger.warning(f"单词 {word_id} 不属于用户 {current_user.id}")
            return jsonify({"error": "单词不存在"}), 404
        
        if request.method == "GET":
            # GET: 获取单词点击统计
            stat = WordClickStat.query.filter_by(
                user_id=current_user.id,
                deckword_id=word_id
            ).first()
            
            if stat:
                # 安全地转换时间戳，确保时区一致
                def safe_timestamp(dt):
                    if dt.tzinfo is None:
                        # 如果是naive datetime，假设它是北京时间
                        dt = dt.replace(tzinfo=BEIJING_TZ)
                    return int(dt.timestamp() * 1000)
                
                return jsonify({
                    "count": stat.click_count,
                    "lastClickTime": safe_timestamp(stat.last_click_time),
                    "firstClickTime": safe_timestamp(stat.first_click_time)
                })
            else:
                return jsonify({
                    "count": 0,
                    "lastClickTime": None,
                    "firstClickTime": None
                })
        
        elif request.method == "POST":
            # POST: 记录/更新单词点击（优化版：防止死锁）
            from sqlalchemy.exc import OperationalError
            import time
            
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    now = now_beijing()
                    
                    # 查找现有统计记录
                    stat = WordClickStat.query.filter_by(
                        user_id=current_user.id,
                        deckword_id=word_id
                    ).first()
                    
                    if stat:
                        # 检查34分钟防重复机制
                        last_click_time = stat.last_click_time
                        if last_click_time.tzinfo is None:
                            last_click_time = last_click_time.replace(tzinfo=BEIJING_TZ)
                        elif last_click_time.tzinfo != BEIJING_TZ:
                            last_click_time = last_click_time.astimezone(BEIJING_TZ)
                        
                        time_diff_minutes = (now - last_click_time).total_seconds() / 60
                        
                        if time_diff_minutes >= 34:  # 34分钟阈值
                            stat.click_count += 1
                            stat.last_click_time = now
                            stat.updated_at = now
                            db.session.commit()
                            
                            def safe_timestamp(dt):
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=BEIJING_TZ)
                                return int(dt.timestamp() * 1000)
                            
                            return jsonify({
                                "count": stat.click_count,
                                "lastClickTime": safe_timestamp(stat.last_click_time),
                                "firstClickTime": safe_timestamp(stat.first_click_time),
                                "updated": True
                            })
                        else:
                            def safe_timestamp(dt):
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=BEIJING_TZ)
                                return int(dt.timestamp() * 1000)
                            
                            return jsonify({
                                "count": stat.click_count,
                                "lastClickTime": safe_timestamp(stat.last_click_time),
                                "firstClickTime": safe_timestamp(stat.first_click_time),
                                "updated": False,
                                "reason": "deduplication"
                            })
                    else:
                        # 创建新的统计记录
                        stat = WordClickStat(
                            user_id=current_user.id,
                            deckword_id=word_id,
                            click_count=1,
                            last_click_time=now,
                            first_click_time=now
                        )
                        db.session.add(stat)
                        db.session.commit()
                        
                        return jsonify({
                            "count": 1,
                            "lastClickTime": int(now.timestamp() * 1000),
                            "firstClickTime": int(now.timestamp() * 1000),
                            "updated": True
                        })
                    break
                
                except OperationalError as e:
                    db.session.rollback()
                    if 'Deadlock' in str(e) and attempt < max_retries - 1:
                        sleep_time = 0.1 * (2 ** attempt)
                        current_app.logger.warning(f"单词点击统计死锁，{sleep_time:.1f}秒后重试 (attempt {attempt + 1}/{max_retries}): {e}")
                        time.sleep(sleep_time)
                        continue
                    else:
                        current_app.logger.error(f"单词点击统计数据库操作失败: {e}")
                        raise
                except Exception as e:
                    db.session.rollback()
                    current_app.logger.error(f"word_click_stats POST 发生未知错误: {e}")
                    raise
            
    except Exception as e:
        current_app.logger.error(f"处理单词点击统计失败: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@vocab_bp.post("/api/migrate_click_stats")
@login_required
def migrate_click_stats():
    """从localStorage迁移点击统计数据到服务器（优化版：批量处理）"""
    from sqlalchemy.exc import OperationalError
    import time
    
    try:
        data = request.get_json()
        local_stats = data.get('stats', {})
        
        if not local_stats:
            return jsonify({"migrated_count": 0, "total_local": 0})
        
        # 防止重复迁移：检查是否有标记
        cache_key = f"migrate_in_progress_{current_user.id}"
        if hasattr(migrate_click_stats, cache_key):
            return jsonify({"migrated_count": 0, "message": "迁移正在进行中"})
        
        setattr(migrate_click_stats, cache_key, True)
        
        try:
            migrated_count = 0
            max_retries = 3
            
            for attempt in range(max_retries):
                try:
                    # 批量获取所有需要的word_id，减少查询次数
                    word_ids = []
                    for word_id_str in local_stats.keys():
                        try:
                            word_ids.append(int(word_id_str))
                        except ValueError:
                            continue
                    
                    if not word_ids:
                        break
                    
                    # 一次性验证所有单词是否属于当前用户
                    valid_words = {w.id: w for w in DeckWord.query.filter(
                        DeckWord.id.in_(word_ids),
                        DeckWord.user_id == current_user.id
                    ).all()}
                    
                    # 一次性获取所有现有统计记录
                    existing_stats = {s.deckword_id: s for s in WordClickStat.query.filter(
                        WordClickStat.user_id == current_user.id,
                        WordClickStat.deckword_id.in_(word_ids)
                    ).all()}
                    
                    # 批量处理
                    batch_size = 50
                    processed = 0
                    
                    for word_id_str, stat_data in local_stats.items():
                        try:
                            word_id = int(word_id_str)
                            
                            if word_id not in valid_words:
                                continue
                            
                            if word_id not in existing_stats:
                                # 创建新记录
                                first_click_time = datetime.fromtimestamp(stat_data['firstClickTime'] / 1000)
                                last_click_time = datetime.fromtimestamp(stat_data['lastClickTime'] / 1000)
                                
                                new_stat = WordClickStat(
                                    user_id=current_user.id,
                                    deckword_id=word_id,
                                    click_count=stat_data['count'],
                                    first_click_time=first_click_time,
                                    last_click_time=last_click_time
                                )
                                db.session.add(new_stat)
                                migrated_count += 1
                            else:
                                # 合并数据：保留最大计数和最早/最晚时间
                                existing_stat = existing_stats[word_id]
                                local_first = datetime.fromtimestamp(stat_data['firstClickTime'] / 1000)
                                local_last = datetime.fromtimestamp(stat_data['lastClickTime'] / 1000)
                                
                                existing_stat.click_count = max(existing_stat.click_count, stat_data['count'])
                                if local_first < existing_stat.first_click_time:
                                    existing_stat.first_click_time = local_first
                                if local_last > existing_stat.last_click_time:
                                    existing_stat.last_click_time = local_last
                                existing_stat.updated_at = now_beijing()
                            
                            processed += 1
                            
                            # 分批提交，减少锁定时间
                            if processed % batch_size == 0:
                                db.session.commit()
                            
                        except (ValueError, KeyError) as e:
                            current_app.logger.warning(f"迁移数据格式错误 word_id={word_id_str}: {e}")
                            continue
                    
                    # 提交剩余的记录
                    db.session.commit()
                    break
                    
                except OperationalError as e:
                    db.session.rollback()
                    if 'Deadlock' in str(e) and attempt < max_retries - 1:
                        sleep_time = 0.2 * (2 ** attempt)
                        current_app.logger.warning(f"点击统计迁移死锁，{sleep_time:.1f}秒后重试 (attempt {attempt + 1}/{max_retries}): {e}")
                        time.sleep(sleep_time)
                        continue
                    else:
                        current_app.logger.error(f"点击统计迁移数据库操作失败: {e}")
                        raise
                except Exception as e:
                    db.session.rollback()
                    current_app.logger.error(f"migrate_click_stats 发生未知错误: {e}")
                    raise
            
            return jsonify({
                "migrated_count": migrated_count,
                "total_local": len(local_stats)
            })
            
        finally:
            # 清除进行中标记
            if hasattr(migrate_click_stats, cache_key):
                delattr(migrate_click_stats, cache_key)
                
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"迁移点击统计失败: {e}")
        return jsonify({"error": "迁移失败"}), 500


# ======================= 用户删除功能 =======================

@vocab_bp.post("/api/get_user_info_for_delete")
@login_required
def api_get_user_info_for_delete():
    """获取指定用户名的基本信息（用于删除确认）"""
    try:
        data = request.get_json(silent=True) or {}
        target_username = (data.get("username") or "").strip()
        
        if not target_username:
            return jsonify({"ok": False, "message": "用户名不能为空"}), 400
        
        # 查找用户
        target_user = User.query.filter_by(username=target_username).first()
        if not target_user:
            return jsonify({"ok": False, "message": "用户不存在"}), 404
        
        # 统计用户数据
        word_count = DeckWord.query.filter_by(user_id=target_user.id).count()
        review_count = ReviewState.query.filter_by(user_id=target_user.id).count()
        click_count = WordClickStat.query.filter_by(user_id=target_user.id).count()
        
        # 获取用户偏好信息
        deck_name = db.session.execute(text(
            "SELECT COALESCE(deck_name,'未命名词库') FROM vocab_userpref WHERE user_id=:uid"
        ), {"uid": target_user.id}).scalar() or "未命名词库"
        
        # 获取创建时间（如果有的话）
        created_time = None
        if hasattr(target_user, 'created_at') and target_user.created_at:
            created_time = target_user.created_at.strftime("%Y-%m-%d %H:%M:%S")
        
        user_info = {
            "username": target_user.username,
            "word_count": word_count,
            "review_count": review_count,
            "click_count": click_count,
            "deck_name": deck_name,
            "created_time": created_time
        }
        
        return jsonify({
            "ok": True,
            "user_info": user_info
        })
        
    except Exception as e:
        current_app.logger.exception("获取用户信息失败: %s", e)
        return jsonify({"ok": False, "message": f"获取用户信息失败: {type(e).__name__}: {e}"}), 500


@vocab_bp.post("/api/delete_user_account")
@login_required
def api_delete_user_account():
    """删除用户账户及其所有数据"""
    try:
        data = request.get_json(silent=True) or {}
        target_username = (data.get("username") or "").strip()
        confirm_password = data.get("confirm_password") or ""
        
        if not target_username or not confirm_password:
            return jsonify({"ok": False, "message": "用户名和确认密码不能为空"}), 400
        
        # 验证确认密码
        if not check_password_hash(current_user.password_hash, confirm_password):
            return jsonify({"ok": False, "message": "确认密码错误"}), 403
        
        # 查找要删除的用户
        target_user = User.query.filter_by(username=target_username).first()
        if not target_user:
            return jsonify({"ok": False, "message": "用户不存在"}), 404
        
        # 防止删除当前登录用户
        if target_user.id == current_user.id:
            return jsonify({"ok": False, "message": "不能删除当前登录的用户"}), 400
        
        # 开始删除操作
        deleted_data = {
            "username": target_user.username,
            "word_count": 0,
            "review_count": 0,
            "click_count": 0,
            "user_pref_deleted": False
        }
        
        # 删除所有相关数据
        # 1. 删除单词点击统计
        click_count = WordClickStat.query.filter_by(user_id=target_user.id).count()
        WordClickStat.query.filter_by(user_id=target_user.id).delete(synchronize_session=False)
        deleted_data["click_count"] = click_count
        
        # 2. 删除复习状态
        review_count = ReviewState.query.filter_by(user_id=target_user.id).count()
        ReviewState.query.filter_by(user_id=target_user.id).delete(synchronize_session=False)
        deleted_data["review_count"] = review_count
        
        # 3. 删除词汇
        word_count = DeckWord.query.filter_by(user_id=target_user.id).count()
        DeckWord.query.filter_by(user_id=target_user.id).delete(synchronize_session=False)
        deleted_data["word_count"] = word_count
        
        # 4. 删除用户偏好
        user_pref_count = UserPref.query.filter_by(user_id=target_user.id).count()
        if user_pref_count > 0:
            UserPref.query.filter_by(user_id=target_user.id).delete(synchronize_session=False)
            deleted_data["user_pref_deleted"] = True
        
        # 5. 最后删除用户账户
        db.session.delete(target_user)
        
        # 提交事务
        db.session.commit()
        
        
        return jsonify({
            "ok": True,
            "message": f"用户 {target_username} 及其所有数据已成功删除",
            "deleted_data": deleted_data
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("删除用户失败: %s", e)
        return jsonify({"ok": False, "message": f"删除用户失败: {type(e).__name__}: {e}"}), 500


# ======================= 完整排行榜导出功能 =======================

@vocab_bp.get("/api/export_complete_ranking")
@login_required
def api_export_complete_ranking():
    """获取完整的排行榜数据用于导出，包含所有详细信息"""
    try:
        uid = current_user.id
        min_clicks = request.args.get('min_clicks', 1, type=int)
        
        # 查询点击统计数据，连接词汇和复习状态
        query = (db.session.query(WordClickStat, DeckWord, ReviewState)
                .join(DeckWord, WordClickStat.deckword_id == DeckWord.id)
                .outerjoin(ReviewState, (ReviewState.user_id == uid) & (ReviewState.deckword_id == DeckWord.id))
                .filter(WordClickStat.user_id == uid)
                .filter(DeckWord.user_id == uid)
                .filter(WordClickStat.click_count >= min_clicks)
                .order_by(WordClickStat.click_count.desc(), WordClickStat.last_click_time.desc()))
        
        results = query.all()
        
        complete_data = []
        for rank, (stat, word, review_state) in enumerate(results, 1):
            # 计算时间跨度
            if stat.first_click_time:
                try:
                    if stat.first_click_time.tzinfo is None:
                        db_time = stat.first_click_time.replace(tzinfo=BEIJING_TZ)
                    else:
                        db_time = stat.first_click_time
                    
                    now = now_beijing()
                    time_diff = now - db_time
                    time_ago = format_time_diff(time_diff.total_seconds())
                except Exception:
                    time_ago = "时间计算错误"
            else:
                time_ago = "未知"
            
            # 构建完整的词汇信息，格式与错词本保持一致
            # 复习状态信息（如果存在）
            if review_state:
                review_status = {
                    "上次间隔小时": getattr(review_state, 'last_interval_hours', None),
                    "下次复习": review_state.next_due.strftime("%Y-%m-%d %H:%M") if review_state.next_due else None,
                    "困难连击次数": getattr(review_state, 'hard_streak', 0) or 0,
                    "最后复习时间": review_state.last_reviewed.strftime("%Y-%m-%d %H:%M") if hasattr(review_state, 'last_reviewed') and review_state.last_reviewed else None,
                    "最后评分": review_state.last_grade,
                    "连续Easy次数": getattr(review_state, 'consec_easy', 0) or 0,
                    "错误次数": review_state.wrong_count or 0
                }
            else:
                review_status = {
                    "上次间隔小时": None,
                    "下次复习": None,
                    "困难连击次数": 0,
                    "最后复习时间": None,
                    "最后评分": None,
                    "连续Easy次数": 0,
                    "错误次数": 0
                }

            # 按照错词本的字段顺序构建数据
            word_data = {
                "中文释义": word.zh or "",  # 完整的中文释义，不截断
                "复习状态": review_status,
                "排名": rank,
                "时间跨度": time_ago,
                "最后点击": stat.last_click_time.strftime("%Y-%m-%d %H:%M") if stat.last_click_time else None,
                "点击次数": stat.click_count,
                "英文": word.en,
                "词汇ID": word.id,
                "首次点击": stat.first_click_time.strftime("%Y-%m-%d %H:%M") if stat.first_click_time else None
            }
            
            complete_data.append(word_data)
        
        return jsonify({
            "ok": True,
            "total_count": len(complete_data),
            "min_clicks": min_clicks,
            "export_time": now_beijing().strftime("%Y-%m-%d %H:%M:%S"),
            "data": complete_data
        })
        
    except Exception as e:
        current_app.logger.exception("export_complete_ranking failed: %s", e)
        return jsonify({
            "ok": False,
            "message": f"导出完整排行榜失败: {type(e).__name__}: {e}"
        }), 500


@vocab_bp.route("/api/current_user", methods=["GET"])
@login_required
def api_current_user():
    """获取当前登录用户信息"""
    try:
        return jsonify({
            "success": True,
            "user_id": current_user.id,
            "username": current_user.username
        })
    except Exception as e:
        current_app.logger.error(f"获取当前用户信息失败: {e}")
        return jsonify({
            "success": False,
            "error": "未登录或获取用户信息失败"
        }), 401


# ======================= v2 分页/批量接口 =======================
V2_MAX_LIMIT = 233
V2_DEFAULT_LIMIT = 55
V2_SUPPORTED_SORTS = {"en_asc", "en_desc", "created_desc", "created_asc", "random"}


def _v2_random_order_clause(seed=None):
    bind = db.session.get_bind()
    dialect = getattr(getattr(bind, "dialect", None), "name", "") or ""
    dial = dialect.lower()
    if dial.startswith("mysql"):
        return func.rand(seed)
    return func.random()


def _v2_b64_encode(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _v2_b64_decode(token: Optional[str]):
    if not token:
        return None
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _v2_normalize_pool(req_pool: Optional[str]) -> str:
    pool = (req_pool or "").lower().strip()
    if pool == "all":
        pool = "easy"
    if pool in ("easy", "good", "hard"):
        return pool
    return None


def _v2_apply_pool_filter(query, pool: str, uid: int):
    base = query.filter(DeckWord.user_id == uid)
    if pool == "good":
        base = base.filter(ReviewState.last_grade == 4)
    elif pool == "hard":
        base = base.filter(
            or_(
                and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
                and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0),
            )
        )
    return base


def _v2_apply_search(query, q: str):
    if not q:
        return query
    field = None
    needle = q.strip()
    ql = needle.lower()
    if ql.startswith("en:"):
        field = "en"
        needle = needle[3:].strip()
    elif ql.startswith("zh:"):
        field = "zh"
        needle = needle[3:].strip()
    if not needle:
        return query

    def _prefix_like(col, prefix: str):
        return func.lower(col).like(f"{prefix.lower()}%")

    if field == "en":
        if needle.startswith("^"):
            return query.filter(_prefix_like(DeckWord.en, needle[1:]))
        return query.filter(ci_like(DeckWord.en, needle))
    if field == "zh":
        if needle.startswith("^"):
            return query.filter(_prefix_like(DeckWord.zh, needle[1:]))
        return query.filter(ci_like(DeckWord.zh, needle))

    tokens = [token for token in needle.split() if token]
    for token in tokens:
        query = query.filter(or_(ci_like(DeckWord.en, token), ci_like(DeckWord.zh, token)))
    return query


def _v2_serialize_word(word: DeckWord, state: Optional[ReviewState]):
    next_due = state.next_due.isoformat() + "Z" if state and state.next_due else None
    last_grade = int(state.last_grade) if state and state.last_grade is not None else None
    wrong_count = int(state.wrong_count) if state and state.wrong_count else 0
    created_at = word.created_at.isoformat() + "Z" if getattr(word, "created_at", None) else None
    updated_at = word.updated_at.isoformat() + "Z" if getattr(word, "updated_at", None) else None
    return {
        "id": word.id,
        "en": word.en,
        "zh": word.zh,
        "last_grade": last_grade,
        "wrong_count": wrong_count,
        "next_due": next_due,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _v2_apply_cursor(query, sort_mode: str, payload: Optional[dict]):
    if not payload:
        return query
    if sort_mode in ("en_asc", "en_desc"):
        key = str(payload.get("key") or "")
        word_id = payload.get("id")
        if word_id is None:
            return query
        if sort_mode == "en_asc":
            return query.filter(
                or_(
                    func.lower(DeckWord.en) > key,
                    and_(func.lower(DeckWord.en) == key, DeckWord.id > word_id),
                )
            )
        return query.filter(
            or_(
                func.lower(DeckWord.en) < key,
                and_(func.lower(DeckWord.en) == key, DeckWord.id < word_id),
            )
        )
    if sort_mode in ("created_desc", "created_asc"):
        created_at_raw = payload.get("created_at")
        word_id = payload.get("id")
        if not created_at_raw or word_id is None:
            return query
        try:
            created_at = datetime.fromisoformat(created_at_raw)
        except ValueError:
            return query
        if sort_mode == "created_desc":
            return query.filter(
                or_(
                    DeckWord.created_at < created_at,
                    and_(DeckWord.created_at == created_at, DeckWord.id < word_id),
                )
            )
        return query.filter(
            or_(
                DeckWord.created_at > created_at,
                and_(DeckWord.created_at == created_at, DeckWord.id > word_id),
            )
        )
    return query


def _v2_build_order(sort_mode: str):
    if sort_mode == "en_desc":
        return [func.lower(DeckWord.en).desc(), DeckWord.id.desc()]
    if sort_mode == "created_desc":
        return [DeckWord.created_at.desc(), DeckWord.id.desc()]
    if sort_mode == "created_asc":
        return [DeckWord.created_at.asc(), DeckWord.id.asc()]
    return [func.lower(DeckWord.en).asc(), DeckWord.id.asc()]


def _v2_next_cursor_payload(sort_mode: str, word: DeckWord):
    payload = {"id": word.id, "sort": sort_mode}
    if sort_mode in ("en_asc", "en_desc"):
        payload["key"] = (word.en or "").lower()
    elif sort_mode in ("created_desc", "created_asc") and getattr(word, "created_at", None):
        payload["created_at"] = word.created_at.isoformat()
    return payload


def _v2_resolve_limit():
    try:
        limit = int(request.args.get("limit", V2_DEFAULT_LIMIT))
    except Exception:
        limit = V2_DEFAULT_LIMIT
    return max(1, min(V2_MAX_LIMIT, limit))


@vocab_bp.get("/api/v2/words")
@login_required
def api_v2_words():
    uid = current_user.id
    raw_sort = (request.args.get("sort") or "en_asc").lower()
    sort_mode = raw_sort if raw_sort in V2_SUPPORTED_SORTS else "en_asc"
    req_pool = request.args.get("pool") or ""
    pool = _v2_normalize_pool(req_pool)
    if pool is None:
        pool = db.session.execute(
            text("SELECT COALESCE(study_pool,'easy') FROM vocab_userpref WHERE user_id=:uid"),
            {"uid": uid},
        ).scalar() or "easy"
    q = (request.args.get("q") or "").strip()
    include_total = (request.args.get("include_total") or "0") in ("1", "true", "True")
    limit = _v2_resolve_limit()
    cursor_payload = _v2_b64_decode(request.args.get("cursor"))
    seed = request.args.get("seed") or (cursor_payload or {}).get("seed") or secrets.token_hex(4)

    base_query = (
        db.session.query(DeckWord, ReviewState)
        .outerjoin(
            ReviewState,
            (ReviewState.user_id == uid) & (ReviewState.deckword_id == DeckWord.id),
        )
    )
    base_query = _v2_apply_pool_filter(base_query, pool, uid)
    base_query = _v2_apply_search(base_query, q)

    total_count = None
    if include_total:
        total_count = base_query.count()

    if sort_mode == "random":
        offset = 0
        if cursor_payload and isinstance(cursor_payload.get("offset"), int):
            offset = max(0, cursor_payload["offset"])
        rows = (
            base_query.order_by(_v2_random_order_clause(seed))
            .offset(offset)
            .limit(limit + 1)
            .all()
        )
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more:
            next_cursor = _v2_b64_encode({"offset": offset + limit, "seed": seed, "sort": sort_mode})
    else:
        ordered = _v2_apply_cursor(base_query, sort_mode, cursor_payload)
        ordered = ordered.order_by(*_v2_build_order(sort_mode))
        rows = ordered.limit(limit + 1).all()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more and rows:
            payload = _v2_next_cursor_payload(sort_mode, rows[-1][0])
            next_cursor = _v2_b64_encode(payload)

    items = [_v2_serialize_word(word, state) for word, state in rows]
    meta = {"pool": pool, "sort": sort_mode}
    if q:
        meta["query"] = q
    if sort_mode == "random":
        meta["seed"] = seed
    if total_count is not None:
        meta["total"] = total_count

    return jsonify({
        "ok": True,
        "items": items,
        "page_info": {"has_more": has_more, "next_cursor": next_cursor},
        "meta": meta,
    })


@vocab_bp.get("/api/v2/next_cards")
@login_required
def api_v2_next_cards():
    uid = current_user.id
    req_pool = request.args.get("pool") or ""
    pool = _v2_normalize_pool(req_pool)
    if pool is None:
        pool = db.session.execute(
            text("SELECT COALESCE(study_pool,'easy') FROM vocab_userpref WHERE user_id=:uid"),
            {"uid": uid},
        ).scalar() or "easy"
    include_new = (request.args.get("include_new") or "1") not in ("0", "false", "False")
    limit = _v2_resolve_limit()
    window = max(0, min(3600, int(request.args.get("soft_window_seconds", 300) or 300)))
    now = datetime.utcnow()
    until = now + timedelta(seconds=window)

    base_review = (
        db.session.query(ReviewState, DeckWord)
        .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
        .filter(ReviewState.user_id == uid)
    )
    if pool == "good":
        base_review = base_review.filter(ReviewState.last_grade == 4)
    elif pool == "hard":
        base_review = base_review.filter(
            or_(
                and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
                and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0),
            )
        )

    review_rows = (
        base_review.filter(ReviewState.next_due <= until)
        .order_by(ReviewState.next_due.asc())
        .limit(limit)
        .all()
    )
    review_items = []
    earliest_next = None
    for state, word in review_rows:
        early_seconds = int(max(0, (state.next_due - now).total_seconds())) if state.next_due else 0
        review_items.append({
            "type": "review",
            "word": _v2_serialize_word(word, state),
            "due_time": state.next_due.replace(microsecond=0).isoformat() + "Z" if state.next_due else None,
            "early_seconds": early_seconds,
        })
        if earliest_next is None or (state.next_due and state.next_due < earliest_next):
            earliest_next = state.next_due

    results = list(review_items)

    to_fill = max(0, limit - len(review_items))
    new_cursor = None
    new_items = []
    if include_new and pool == "easy" and to_fill > 0:
        pref = _get_or_create_pref(uid)
        mode = (pref.sort_mode or "asc").lower()
        subq = db.session.query(ReviewState.deckword_id).filter(ReviewState.user_id == uid)
        base_new = DeckWord.query.filter(DeckWord.user_id == uid, ~DeckWord.id.in_(subq))
        picked = []
        remain = to_fill

        if mode == "random":
            total_new = base_new.count()
            tried = set()
            while remain > 0 and total_new > 0 and len(tried) < min(total_new, remain * 3):
                offset = random.randint(0, max(0, total_new - 1))
                if offset in tried:
                    continue
                tried.add(offset)
                candidate = base_new.order_by(func.lower(DeckWord.en).asc()).offset(offset).first()
                if candidate and candidate.id not in {w.id for w in picked}:
                    picked.append(candidate)
                    remain -= 1
        elif mode == "desc":
            marker = pref.last_en_marker or ""
            q1 = base_new.filter(DeckWord.en < marker) if marker else base_new
            part1 = q1.order_by(func.lower(DeckWord.en).desc()).limit(remain).all()
            picked.extend(part1)
            if len(picked) < limit:
                need = limit - len(picked)
                part2 = base_new.order_by(func.lower(DeckWord.en).desc()).limit(need).all()
                existing = {w.id for w in picked}
                part2 = [w for w in part2 if w.id not in existing]
                picked.extend(part2)
            if picked:
                pref.last_en_marker = picked[-1].en
                db.session.commit()
        else:
            marker = pref.last_en_marker or ""
            q1 = base_new.filter(DeckWord.en > marker) if marker else base_new
            part1 = q1.order_by(func.lower(DeckWord.en).asc()).limit(remain).all()
            picked.extend(part1)
            if len(picked) < limit:
                need = limit - len(picked)
                part2 = base_new.order_by(func.lower(DeckWord.en).asc()).limit(need).all()
                existing = {w.id for w in picked}
                part2 = [w for w in part2 if w.id not in existing]
                picked.extend(part2)
            if picked:
                pref.last_en_marker = picked[-1].en
                db.session.commit()

        take = picked[:max(0, limit - len(review_items))]
        for word in take:
            new_items.append({
                "type": "new",
                "word": _v2_serialize_word(word, None),
                "due_time": None,
                "early_seconds": 0,
            })

        if take and mode in ("asc", "desc"):
            payload = _v2_next_cursor_payload("en_asc" if mode == "asc" else "en_desc", take[-1])
            new_cursor = _v2_b64_encode(payload)

    results.extend(new_items)
    return jsonify({
        "ok": True,
        "items": results,
        "window_seconds": window,
        "meta": {
            "pool": pool,
            "review_count": len(review_items),
            "new_count": len(new_items),
            "earliest_next_due": earliest_next.isoformat() + "Z" if earliest_next else None,
            "new_cursor": new_cursor,
        },
    })


@vocab_bp.get("/api/v2/bootstrap")
@login_required
def api_v2_bootstrap():
    """
    首屏预取接口：一次性返回 me、prefs、stats 和 initial_cards
    - 首屏预取限定 8 张卡片
    - 5 秒用户级缓存
    """
    uid = current_user.id

    # 尝试从缓存获取
    cached = _get_bootstrap_cache(uid)
    if cached:
        return jsonify(cached)

    # 1. 获取用户信息
    me = {"logged_in": True, "username": current_user.username}

    # 2. 获取偏好设置
    pref = _get_or_create_pref(uid)
    pool = db.session.execute(
        text("SELECT COALESCE(study_pool,'easy') FROM vocab_userpref WHERE user_id=:uid"),
        {"uid": uid}
    ).scalar() or "easy"
    deck_name = db.session.execute(
        text("SELECT COALESCE(deck_name,'未命名词库') FROM vocab_userpref WHERE user_id=:uid"),
        {"uid": uid}
    ).scalar() or "未命名词库"

    prefs = {
        "ok": True,
        "sort_mode": pref.sort_mode if pref else "asc",
        "last_en_marker": pref.last_en_marker if pref else None,
        "study_pool": pool,
        "deck_name": deck_name
    }

    # 3. 获取统计信息
    stats = _calc_stats_for_user(uid)
    stats["ok"] = True
    stats["rev"] = int((pref.stats_rev if pref else 0) or 0)

    # 4. 获取初始卡片（限定8张）
    initial_limit = 8
    window = 300
    now = datetime.utcnow()
    until = now + timedelta(seconds=window)

    base_review = (
        db.session.query(ReviewState, DeckWord)
        .join(DeckWord, DeckWord.id == ReviewState.deckword_id)
        .filter(ReviewState.user_id == uid)
    )

    # 根据 pool 过滤
    if pool == "good":
        base_review = base_review.filter(ReviewState.last_grade == 4)
    elif pool == "hard":
        base_review = base_review.filter(
            or_(
                and_(ReviewState.last_grade.isnot(None), ReviewState.last_grade < 3),
                and_(ReviewState.last_grade.is_(None), ReviewState.wrong_count > 0)
            )
        )

    # 获取到期卡片
    review_rows = (
        base_review.filter(ReviewState.next_due <= until)
        .order_by(ReviewState.next_due.asc())
        .limit(initial_limit)
        .all()
    )

    initial_cards = []
    for state, word in review_rows:
        early_seconds = int(max(0, (state.next_due - now).total_seconds())) if state.next_due else 0
        initial_cards.append({
            "type": "review",
            "word": _v2_serialize_word(word, state),
            "due_time": state.next_due.replace(microsecond=0).isoformat() + "Z" if state.next_due else None,
            "early_seconds": early_seconds
        })

    # 如果复习卡片不足 8 张，用新卡补足（仅在 pool=easy 时）
    to_fill = max(0, initial_limit - len(initial_cards))
    if pool == "easy" and to_fill > 0:
        mode = (pref.sort_mode or "asc").lower()
        subq = db.session.query(ReviewState.deckword_id).filter(ReviewState.user_id == uid)
        base_new = DeckWord.query.filter(DeckWord.user_id == uid, ~DeckWord.id.in_(subq))

        if mode == "random":
            total_new = base_new.count()
            picked = []
            tried = set()
            remain = to_fill
            while remain > 0 and total_new > 0 and len(tried) < min(total_new, remain * 3):
                offset = random.randint(0, max(0, total_new - 1))
                if offset in tried:
                    continue
                tried.add(offset)
                candidate = base_new.order_by(func.lower(DeckWord.en).asc()).offset(offset).first()
                if candidate and candidate.id not in {w.id for w in picked}:
                    picked.append(candidate)
                    remain -= 1
        elif mode == "desc":
            marker = pref.last_en_marker or ""
            q1 = base_new.filter(DeckWord.en < marker) if marker else base_new
            picked = q1.order_by(func.lower(DeckWord.en).desc()).limit(to_fill).all()
        else:  # asc
            marker = pref.last_en_marker or ""
            q1 = base_new.filter(DeckWord.en > marker) if marker else base_new
            picked = q1.order_by(func.lower(DeckWord.en).asc()).limit(to_fill).all()

        for word in picked:
            initial_cards.append({
                "type": "new",
                "word": _v2_serialize_word(word, None),
                "due_time": None,
                "early_seconds": 0
            })

    # 构建响应
    response_data = {
        "ok": True,
        "me": me,
        "prefs": prefs,
        "stats": stats,
        "initial_cards": initial_cards,
        "window_seconds": window
    }

    # 设置缓存
    _set_bootstrap_cache(uid, response_data)

    return jsonify(response_data)

