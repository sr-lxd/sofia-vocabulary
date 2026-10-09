# vocab_pro/models.py
from datetime import datetime, timedelta, timezone
from sqlalchemy import UniqueConstraint, Index
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db

# 北京时区（UTC+8）
BEIJING_TZ = timezone(timedelta(hours=8))

def now_beijing():
    """获取北京时间"""
    return datetime.now(BEIJING_TZ)


# ---------------- User ----------------
class User(db.Model, UserMixin):
    __tablename__ = "vocab_user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=now_beijing, nullable=False)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)


# ---------------- 取词/偏好 ----------------
class UserPref(db.Model):
    __tablename__ = "vocab_userpref"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("vocab_user.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    # asc / desc / random
    sort_mode = db.Column(db.String(16), default="asc", nullable=False)
    # 新词流锚点（允许长 en）
    last_en_marker = db.Column(db.Text)
    # 统计版本号（每次复习提交后 +1，用于乱序响应裁决）
    stats_rev = db.Column(db.Integer, default=0, nullable=False)
    study_pool = db.Column(db.String(8), default="easy", nullable=False)
    deck_name = db.Column(db.String(255), default="未命名词库", nullable=False)

    updated_at = db.Column(db.DateTime, default=now_beijing, onupdate=now_beijing, nullable=False)
    created_at = db.Column(db.DateTime, default=now_beijing, nullable=False)


# ---------------- DeckWord ----------------
class DeckWord(db.Model):
    __tablename__ = "vocab_deckword"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("vocab_user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # 支持长英文
    en = db.Column(db.Text, nullable=False)
    # 长中文释义/例句
    zh = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=now_beijing)

    __table_args__ = (
        UniqueConstraint("user_id", "en", name="uq_vocab_user_en"),
        Index("ix_vocab_deckword_en", "en"),
    )


# ---------------- ReviewState ----------------
class ReviewState(db.Model):
    __tablename__ = "vocab_reviewstate"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("vocab_user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    deckword_id = db.Column(
        db.Integer,
        db.ForeignKey("vocab_deckword.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    ease = db.Column(db.Float, default=2.5)
    interval_days = db.Column("interval", db.Integer, default=0)
    reps = db.Column("repetitions", db.Integer, default=0)
    next_due = db.Column(db.DateTime, default=now_beijing, index=True)

    wrong_count = db.Column(db.Integer, default=0)
    last_grade = db.Column(db.Integer)
    consec_easy = db.Column(db.Integer, default=0, nullable=False)
    hard_streak = db.Column(db.Integer, default=0, nullable=False)
    last_interval_hours = db.Column(db.Float)
    last_reviewed = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=now_beijing)

    __table_args__ = (
        UniqueConstraint("user_id", "deckword_id", name="uniq_user_word"),
        Index("ix_user_due", "user_id", "next_due"),
    )


# ---------------- SM-2 更新逻辑 ----------------
def sm2_update(state: "ReviewState", grade: int):
    now = now_beijing()
    g = max(0, min(5, int(grade)))

    state.last_grade = g
    if g < 3:
        state.wrong_count = (state.wrong_count or 0) + 1

    ef = state.ease or 2.5
    reps = state.reps or 0
    interval = state.interval_days or 0

    if g < 3:
        reps = 0
        interval = 1
    else:
        if reps == 0:
            interval = 1
        elif reps == 1:
            interval = 6
        else:
            interval = round(interval * ef)
        reps += 1
        ef = ef + (0.1 - (5 - g) * (0.08 + (5 - g) * 0.02))
        if ef < 1.3:
            ef = 1.3

    state.ease = ef
    state.reps = reps
    state.interval_days = interval
    state.next_due = now + timedelta(days=interval)
    state.last_reviewed = now


# ---------------- WordClickStat ----------------
class WordClickStat(db.Model):
    __tablename__ = "vocab_word_click_stat"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("vocab_user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    deckword_id = db.Column(
        db.Integer,
        db.ForeignKey("vocab_deckword.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    click_count = db.Column(db.Integer, default=1, nullable=False)
    last_click_time = db.Column(db.DateTime, nullable=False, index=True)
    first_click_time = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=now_beijing, nullable=False)
    updated_at = db.Column(db.DateTime, default=now_beijing, onupdate=now_beijing, nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "deckword_id", name="uniq_user_word_click_stat"),
        Index("ix_user_word_click", "user_id", "deckword_id"),
    )
