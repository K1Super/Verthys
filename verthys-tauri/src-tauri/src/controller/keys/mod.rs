/*
 * controller/keys — 密钥与因子域
 *
 * 职责边界：全局主密钥（GMK）派生/校验/清零、全库密钥修改、keyfile 因子、
 * PCR 策略与设备绑定。所有私钥与派生材料只在 worker 或 DPAPI 边界内存在，
 * 本域只负责输入校验、指令编排与审计。
 */
pub mod device_controller;
pub mod key_change_controller;
pub mod key_controller;
pub mod keyfile_controller;
pub mod pcr_controller;
