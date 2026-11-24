/*
 * tests/kernel-guard/kg_dummy_worker.c — minimal suspended target for ARM/REGISTER tests.
 * It is created with CREATE_SUSPENDED and terminated without ever running.
 */

#include <windows.h>

int wmain(void)
{
    Sleep(60000);
    return 0;
}
