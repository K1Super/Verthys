/*
 * verthys_version.h — 版本语义唯一事实源（公共头）
 *
 * 两个常量分别代表两类互不相同的契约：
 *   VERTHYS_API_VERSION              当前 C ABI 接口集版本（编译期能力探测）
 *   VERTHYS_CONTAINER_FORMAT_VERSION 当前容器格式版本（落盘格式身份）
 *
 * 任何消费方（Rust 构建脚本、worker 兼容门、升级清单）都必须从本头解析，
 * 禁止在别处重复字面量。
 */
#ifndef VERTHYS_VERSION_H
#define VERTHYS_VERSION_H

#define VERTHYS_API_VERSION 0x0014u
#define VERTHYS_CONTAINER_FORMAT_VERSION 4u

#endif /* VERTHYS_VERSION_H */
