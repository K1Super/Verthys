/* 调用方验签正向对照宿主：只加载生产 DLL 并调用 Verthys_Init / Verthys_Deinit。
 *
 * 与其它测试工具不同，本程序链接 verthys.dll 而非对象库，这样调用方
 * 签名校验才会校验“宿主主模块 + DLL 自身”两条路径。退出码约定：
 *   0 = Init 成功；2 = Init 被拒绝（具体返回码打印到 stdout）。
 */
#include "verthys.h"
#include <stdio.h>

int main(void)
{
    VerthysHandle handle = NULL;
    VerthysResult rc = Verthys_Init(&handle);
    printf("INIT result=0x%08X\n", (unsigned)rc);
    if (rc != VERTHYS_OK) {
        fflush(stdout);
        return 2;
    }
    Verthys_Deinit(handle);
    printf("DEINIT ok\n");
    return 0;
}
