from flask import Blueprint

# 统一：模板与静态资源放在 vocab_pro 下
# 前端会通过 /vocab/vocab-static/... 访问到本蓝图的 static 目录
vocab_bp = Blueprint(
    "vocab",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/vocab-static",
)

# 导入路由以完成注册（装饰器绑定在 vocab_bp 上）
from . import routes  # noqa: E402,F401
