/*
 * controller/mod.rs — 控制器层模块入口
 *
 * 控制器层职责：
 *   - 接收上下文，调用服务层或 worker 契约，将错误向上转换
 *   - 允许捕获特定业务异常，转换为具有业务语义的统一错误结构
 *   - 转换后必须立即向上抛出，不得隐式返回空值或默认值掩盖故障
 *   - 禁止直接调用日志发送接口（仅顶层入口层允许）
 *   - 禁止直接访问持久层具体实现，应通过服务层
 *
 * 领域划分（按数据面与信任边界分组，组内高内聚，组间依赖单向）：
 *   - vault      加密库核心：容器生命周期、记录数据面、模块密钥、轮换、回退锚点
 *   - keys       密钥与因子：GMK、keyfile、PCR、设备绑定
 *   - media      照片数据面：导入、查看、导出、备份还原
 *   - filevault  清藏导入：文件保险箱写入流水线
 *   - files      通用文件 I/O：沙箱白名单、用户授权读写、流式落盘
 *   - protection 防护面：防截屏隐私保护、剪贴板清理
 *   - ops        运维面：诊断日志、开发夹具
 *
 * 组间依赖方向：media / filevault → vault / files；protection / ops 独立；
 * keys 独立。禁止反向依赖，跨组共享能力放在本层根模块（api_error / types）。
 *
 * 依赖方向：controller → service（单向，禁止反向）
 */
/// API 错误码与响应信封（ApiResponse<T> / ApiError / ErrorCode）
pub mod api_error;
/// 跨控制器共享 DTO：记录标识、初始化状态、响应信封、扫描与隐私结果
pub mod types;

/// 通用文件 I/O：沙箱白名单读写、用户授权文件操作、流式落盘
pub mod files;
/// 清藏导入：文件保险箱 native 导入流水线
pub mod filevault;
/// 密钥与因子：GMK 派生/校验、keyfile、PCR、设备绑定
pub mod keys;
/// 照片数据面：native 导入、查看、导出、备份还原
pub mod media;
/// 运维面：诊断日志导出与开发夹具
pub mod ops;
/// 防护面：防截屏隐私保护与剪贴板清理
pub mod protection;
/// 加密库核心：容器生命周期、记录数据面、模块密钥、全库轮换与回退锚点
pub mod vault;
