# Sofia背单词

<!-- en-intro -->
**Sofia Vocabulary** — a personal English vocabulary trainer (Flask + SQLite) with SM-2 spaced repetition, built-in word lists and learning statistics.
<!-- /en-intro -->

---

一个基于 Flask、SQLite 和浏览器界面的个人英语词汇学习项目。项目提供账号注册与登录、个人词库维护、单词复习、学习统计和错词导入导出等功能。默认只监听本机 `127.0.0.1`，适合在自己的 Windows 电脑上运行。

## 功能

- 注册、登录和退出；每个账号拥有独立词库和学习记录。
- 添加、修改、删除和搜索词条，支持自定义词库与词库偏好。
- 基于 SM-2 间隔重复算法安排新词和到期复习。
- 记录复习结果、错词数、单词点击情况和学习统计。
- 导入、导出错词及学习数据；页面提供学习计划和统计视图。
- 内置小学、初中、高考等英语词汇 JSON 数据文件，另有少量新账号示例词条。

具体页面和功能以当前版本代码为准。此项目是个人学习工具，不是托管式多用户服务。

## 环境要求

- Windows 10/11（其他支持 Python 的系统也可尝试）
- Python 3.10 或更高版本
- Git（从源码克隆时需要）

## 安装与启动

在 PowerShell 或 Windows Terminal 中运行：

```powershell
git clone https://github.com/sr-lxd/sofia-vocabulary.git
cd sofia-vocabulary
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python vocab_app.py
```

浏览器打开：<http://127.0.0.1:5050/vocab/>。

如果 PowerShell 阻止虚拟环境激活，可直接使用虚拟环境里的 Python 安装依赖并启动：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe vocab_app.py
```

停止服务时，在启动窗口按 `Ctrl+C`。可通过 `VOCAB_PORT` 环境变量更换本机端口，例如：

```powershell
$env:VOCAB_PORT = "5051"
python vocab_app.py
```

访问地址相应变成 `http://127.0.0.1:5051/vocab/`。服务器绑定 `127.0.0.1`，局域网其他设备无法直接访问。

## 本机运行验证

2026-10-09 在 Windows、Python 3.13.7 环境下启动验证通过。应用监听 `127.0.0.1:5050`；登录页、介绍页、学习页、帮助页、前端脚本和登录状态接口均返回 HTTP 200。临时账号注册、会话登录及词库读取也通过，注册后返回 5 个示例词，测试账号随后已清理。

这是本机冒烟验证记录，不代表对所有学习功能做了完整视觉或自动化回归测试。按上文命令在终端前台启动后，可在同一窗口按 `Ctrl+C` 停止服务。
## 首次使用

1. 打开登录页后注册一个个人账号。
2. 登录后使用默认示例词条，或导入、编辑自己的词库。
3. 开始学习并按提示评定记忆情况，程序会根据复习记录安排下次复习。
4. 使用错词和统计页面查看学习进度。

旧版本中的预设共享账号已从公开版移除。请注册自己的账号。服务端“记住登录”不再保存或返回明文密码。旧数据不会自动迁移到新生成的 `vocab.db`。

## 数据与备份

首次运行时，SQLite 数据库 `vocab.db` 会在项目目录创建。它包含账号、词库、复习状态和统计数据，因此被 `.gitignore` 排除，不会提交到 GitHub。

备份时先停止应用，再复制 `vocab.db` 到安全位置。恢复时停止应用，并用备份文件替换项目目录里的数据库文件。请勿把真实数据库、密码、会话密钥或个人词库提交到公开仓库。

设置 Flask 会话密钥的环境变量示例：

```powershell
$env:FLASK_SECRET_KEY = "请替换为随机且保密的长字符串"
python vocab_app.py
```

若未设置，程序会为当前进程生成临时随机密钥，重启后需要重新登录。不要将真实密钥写入源码或提交到 Git。

## 项目结构

```text
vocab_pro/
├── extensions.py          # SQLAlchemy 与 Flask-Login 扩展
├── run.py                 # Flask 应用工厂和本机启动入口
├── vocab_app.py           # 兼容启动入口
├── models.py              # 用户、词库、复习状态和统计模型
├── routes.py              # 页面与 API 路由
├── templates/             # 登录、学习和统计页面
├── static/                # 前端脚本、样式、图标及构建资源
├── data/                  # 词汇数据集
└── requirements.txt       # Python 依赖
```

## 配置说明

- `FLASK_SECRET_KEY`：Flask 会话签名密钥。应设置为随机长字符串。
- `VOCAB_PORT`：本机监听端口，默认 `5050`。
- 数据库：默认使用项目目录中的 SQLite 文件 `vocab.db`。

## 隐私与使用范围

程序绑定到 `127.0.0.1`，不要通过反向代理或改成 `0.0.0.0` 暴露到公网。该项目未按公网服务做完整的安全加固，也没有多用户托管所需的隔离、运维和备份设计。公开仓库不包含本地 SQLite 数据库、旧路由快照或个人笔记。词汇 JSON 是项目运行所需的数据文件；使用或再分发前，请自行确认其来源及许可。

## 已知限制

- 使用 SQLite，适合个人本机使用，不适合多个用户并发写入。
- 数据库升级目前依赖 SQLAlchemy 的建表能力，没有单独的迁移历史。
- 前端构建产物已随仓库提供；修改前端源码时需按对应构建脚本重新生成。
- 该版本不提供公开部署配置或公网服务承诺。

## 许可证

目前仓库未声明开源许可证。没有许可证时，其他人通常不能默认复制、修改或再分发项目代码。若希望公众自由使用，请在仓库中补充适合的许可证文件。