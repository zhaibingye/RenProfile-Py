# 开发说明

只想使用工具，请先看 [首页的完整入门教程](../README.md)。本页面向阅读源码、测试或自行打包的开发者。

4.0 的入口、执行流程和扫描策略已重写。正常使用只需要根目录的 `RenProfile-<版本号>.exe`。

4.1.0 增加自动改名失败后的手动继续窗口。只有目录改名返回 WinError 5/32/33、用户 hive 已卸载且日志回滚完成，才提供此入口。等待期间不保留工作线程、操作锁或 hive 挂载；用户手动改好后，点击继续会验证同一 SID、原/新路径和目录文件标识及权限，创建新任务重新扫描，再迁移设置。继续失败的回滚保留用户手动改好的目录和兼容入口。4.0.2 的目录改名失败记录也可识别；再次启动程序后选择原用户及相同新名称，可以自动接续。成功时清理本次任务和对应的自动改名失败记录。

发布文件名由源码版本自动生成，例如 `RenProfile-4.1.0.exe`；Windows 文件属性中的产品版本、文件版本和原始文件名也同步写入。运行时副本保留带版本的文件名。

4.0.2 修复工具数据目录权限导致无法启动的问题：按访问条目的实际 SID、权限与继承范围判断，接受等价顺序及当前维护账户的专用权限；工具根目录不符合要求时自动整理其 DACL 和所有者，旧恢复记录保留。整理只针对该目录，以 MAXIMUM_ALLOWED 句柄调用 SetSecurityInfo，避免向子项传播权限；已有记录、目录内链接的外部目标和目标用户文件夹不随之重置。依据：[SetSecurityInfo 的子项传播规则](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)。

4.0.1 补强了中断与清理路径：新任务在操作锁内检查同一用户的未恢复记录；日志损坏时仍保留所属 SID。加载用户 hive 前记录随机挂载名，卸载失败或进程中断后按记录释放，未释放成功不会标为已回滚。显式恢复可以让 SQLite 修复崩溃留下的事务日志，但普通状态查询仍然只读，也不会给未知数据库补建表。

可删除的备份先在原父目录内改为 `cleanup-<随机编号>`，再删除内容。删除中断后仅重试清理，不能触发账户回滚，也不会被当作未完成的迁移。

## 执行流程

- GUI 每次开始清空本次详情；历史记录只在恢复窗口显示。界面选择只提供 SID，新请求再次读取实际 ProfileList。
- 单一 `Engine.migrate` 在操作锁内校验、扫描、改名和更新。每次使用新 UUID 目录；没有接收旧扫描计划的 plan/apply 命令。
- 备份目录中的 plan.json 只保存账户、目录身份、文件位置等恢复元数据。实际修改的前后值保存在 SQLite 写前日志，每一步先落盘再修改。只备份修改位置，不复制用户数据或整个 hive。
- 扫描前读取旧 8.3 路径；扫描结束卸载用户 hive，才改目录名。然后建立旧路径 junction，更新用户设置；卸载 hive 后最后提交原 SID 的 ProfileImagePath。
- 核对新目录文件标识、所有者、组、DACL、SID 路径绑定和 junction。成功删除本次记录；失败反向恢复，失败记录保留。
- 对以前手动改好的目录，会核对旧路径不存在或是指向新目录的 junction、SID 仍绑定旧路径，再补全设置。这种情况下回滚保留手动改名和兼容入口。
- recovery.py 只负责恢复，保留格式 2 的旧记录读取和撤销能力；不会拿旧动作再次迁移。

## 注册表处理

扫描目标 NTUSER.DAT、存在时的 UsrClass.dat 的字符串值，以及机器环境变量和 App Paths 两个注册表视图。值的类型、环境变量占位符保持不变。

不遍历整个 HKLM SOFTWARE/SYSTEM，不访问引发原故障的 StateRepository。用户 AppModel 数据、二进制、键名和值名等内部索引保留原样。其他配置中的旧文件路径由兼容入口继续提供访问。

非关键设置在写入权限预检时被拒绝，会保留原值。执行中只有“拒绝访问且读回证明值完全未变”才允许跳过；部分写入、磁盘错误、无法确定结果等触发回滚。ProfileImagePath 永远不能跳过。

值写入使用 KEY_QUERY_VALUE | KEY_SET_VALUE，不修改注册表权限或接管所有权。[微软访问权限说明](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)。

## 避免工具自身占用目录

发布 EXE 提权后复制到 `%ProgramData%\RenProfile-Py\runtime-<随机编号>`，隐藏的 PowerShell 控制进程等待原 EXE 的应用进程和 onefile 父进程退出，再启动副本。副本的 TEMP/TMP 和工作目录也位于目标用户目录之外。

工作进程退出后，控制进程检查准确的临时目录路径、标记及链接，再清理该目录。失败作业不会被运行时清理触碰。PowerShell 使用系统内置程序，以独立参数传递路径；执行策略参数只针对这个控制进程。

这种启动方式处理工具自身占用，不会结束其他应用、注销用户或关闭系统服务。外部占用仍可能导致改名失败，错误会显示位置和可获得的占用信息。

[PyInstaller 进程与重启说明](https://pyinstaller.org/en/stable/advanced-topics.html)。源码运行时，Python 和源码仍须位于目标用户目录之外。

## 验证和打包

在 Windows x64 上安装 Python 3.11 或更新版本，并确认包含 Tkinter。下列命令在项目根目录运行，开发环境可使用虚拟环境。Python、虚拟环境和源码须放在待改名用户目录之外，源码启动需要满足这一条件；普通用户直接使用 EXE。

```powershell
git clone https://github.com/zhaibingye/RenProfile-Py.git
cd RenProfile-Py
python -m renprofile
```

从源码启动 GUI 也会请求管理员权限。测试和打包无需迁移任何真实账户；安装打包依赖后执行：

```powershell
python -m pip install PyInstaller==6.17.0
python -B -X utf8 tools/build.py
python -B -X utf8 -m unittest discover -s tests -v
```

需要 Windows x64、Python 3.11+；打包需要 PyInstaller 6.17+。中间产物在系统临时目录，输出为根目录的 `RenProfile-<版本号>.exe`。

先打包再跑测试，可同时覆盖发布 EXE 的启动与清理；没有 EXE 时，相应测试会跳过。GitHub Actions 会在 Windows 上用 Python 3.14 构建后运行测试。它验证程序逻辑和临时文件行为，不能替代真实电脑的用户迁移验证。

发布时同步修改 `renprofile/__init__.py` 与 `pyproject.toml` 中的版本，更新首页和版本记录。EXE 作为 GitHub Release 的附件发布，不提交到 Git 源码历史；另附 SHA-256 校验文件。运行时恢复记录、私密配置和本地凭据也不能提交。

项目采用 [MIT 许可证](../LICENSE)。提交改动时请说明具体问题、最终行为和验证结果；需要新增测试时优先覆盖真实失败或回滚场景。

测试包括独立临时目录的实际 NTFS 改名、junction、目录身份和权限校验、故障回滚、重试重新扫描、旧版本恢复、GUI 记录隔离和启动控制进程清理。注册表访问权限测试只创建并删除自己的随机临时项。实际账户映射使用替身测试，不修改真实账户配置。

这些测试不能替代真实账户注销/重启/登录和 AppX、OneDrive、winget 等应用验证。兼容入口只保证旧文件路径有入口，不保证应用数据库或身份校验一定接受新路径。原账户密码、SID 及文件权限不会由工具重建；“所有环境绝对无损”无法普遍保证。

## 可选命令

无参数启动图形界面。命令仅供开发和诊断：

```powershell
python -m renprofile inspect --all
python -m renprofile rename --sid "目标用户SID" --name "NewName"
python -m renprofile status --work-dir "恢复目录"
python -m renprofile recover --work-dir "恢复目录"
python -m renprofile continue --work-dir "自动改名失败的记录目录"
```

status 只读已有记录；支持 `--json` 和 `--show-gaps`。旧 rollback 命令是 recover 的别名，完成记录只清理，不逆向撤销成功迁移。
