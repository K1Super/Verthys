# 构建产物契约生成脚本（由 core/CMakeLists.txt 的 POST_BUILD 以 `cmake -P` 方式调用）。
#
# 职责：在 verthys.dll 链接完成且 .rhat 补丁执行完毕后，计算 DLL 的 SHA-256，
#       将产物事实（DLL 相对路径、哈希、版本、容器格式版本、生成器、构建时刻）
#       写入机器可读的 JSON 契约文件。
#
# 设计意图：仓库内消费方（Rust build.rs、打包脚本）此前按生成器类型猜测 DLL
#       子目录（Ninja 单配置为 build/core/，VS 多配置为 build/core/Release/），
#       猜测落空时 DLL 完整性哈希退化为 None，防守失效。契约化后消费方只读
#       本文件，不存在路径漂移。
#
# 安全性：DLL 路径必须是源目录内的相对路径，契约拒绝越出源目录的产物，
#       防止含 `..` 的路径在消费方解引用时逃逸。
#
# 调用前提（-D 参数）：
#   VER_DLL_PATH     已构建 DLL 的绝对路径
#   VER_OUT_PATH     契约输出文件绝对路径
#   VER_SOURCE_DIR   仓库根目录绝对路径
#   VER_VERSION      产品版本号（PROJECT_VERSION）
#   VER_FMT_VERSION  容器格式版本（须与容器层头文件的版本常量保持一致）
#   VER_GENERATOR    CMake 生成器名称
#   VER_CONFIG       当前构建配置

if(NOT DEFINED VER_DLL_PATH OR NOT DEFINED VER_OUT_PATH OR NOT DEFINED VER_SOURCE_DIR)
    message(FATAL_ERROR "产物契约生成缺少必需参数（VER_DLL_PATH / VER_OUT_PATH / VER_SOURCE_DIR）")
endif()
if(NOT DEFINED VER_VERSION OR NOT DEFINED VER_FMT_VERSION)
    message(FATAL_ERROR "产物契约生成缺少版本参数（VER_VERSION / VER_FMT_VERSION）")
endif()
if(NOT DEFINED VER_GENERATOR OR NOT DEFINED VER_CONFIG)
    message(FATAL_ERROR "产物契约生成缺少构建描述参数（VER_GENERATOR / VER_CONFIG）")
endif()
if(NOT EXISTS "${VER_DLL_PATH}")
    message(FATAL_ERROR "DLL 不存在，无法生成产物契约: ${VER_DLL_PATH}")
endif()

# DLL 相对仓库根的路径：契约供多个消费方使用，必须为可移植相对路径（正斜杠）
file(RELATIVE_PATH _ver_dll_rel "${VER_SOURCE_DIR}" "${VER_DLL_PATH}")
string(REPLACE "\\" "/" _ver_dll_rel "${_ver_dll_rel}")
if(_ver_dll_rel MATCHES "^[.]/|^[.][.]/|^/")
    # 契约只描述源目录内的产物；越界路径在消费方会被当作外部输入拒绝
    message(FATAL_ERROR "DLL 位于源目录之外，无法生成相对契约路径: ${VER_DLL_PATH}")
endif()

file(SHA256 "${VER_DLL_PATH}" _ver_sha256)
string(TIMESTAMP _ver_built_at "%Y-%m-%dT%H:%M:%SZ" UTC)

# JSON 字符串转义：仅需处理反斜杠与双引号，其余字段（版本号/生成器名）为受控格式
function(_ver_escape_json _out _in)
    string(REPLACE "\\" "\\\\" _esc "${_in}")
    string(REPLACE "\"" "\\\"" _esc "${_esc}")
    set(${_out} "${_esc}" PARENT_SCOPE)
endfunction()

_ver_escape_json(_gen_esc "${VER_GENERATOR}")
_ver_escape_json(_cfg_esc "${VER_CONFIG}")
_ver_escape_json(_dll_esc "${_ver_dll_rel}")
_ver_escape_json(_ver_esc "${VER_VERSION}")

set(_ver_json
"{
  \"schema\": 1,
  \"generator\": \"${_gen_esc}\",
  \"config\": \"${_cfg_esc}\",
  \"dll\": \"${_dll_esc}\",
  \"sha256\": \"${_ver_sha256}\",
  \"version\": \"${_ver_esc}\",
  \"fmt_version\": ${VER_FMT_VERSION},
  \"built_at\": \"${_ver_built_at}\"
}
")

# 原子落盘：先写同目录临时文件再重命名，避免构建被中断时留下半成品契约误导消费方
set(_ver_tmp "${VER_OUT_PATH}.tmp")
file(WRITE "${_ver_tmp}" "${_ver_json}")
file(RENAME "${_ver_tmp}" "${VER_OUT_PATH}")