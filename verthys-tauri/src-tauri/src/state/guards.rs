use super::AppState;

/* ------------------------------------------------------------------ *
 * InitLockGuard — RAII 初始化锁守卫                                    *
 * ------------------------------------------------------------------ */

/// RAII 守卫：确保 init_lock 在函数退出时释放
pub struct InitLockGuard<'a> {
    pub state: &'a AppState,
}
impl<'a> Drop for InitLockGuard<'a> {
    fn drop(&mut self) {
        self.state.release_init_lock();
    }
}

/* ------------------------------------------------------------------ *
 * KeyOpGuard — RAII 密钥操作锁守卫                                    *
 * ------------------------------------------------------------------ */

/// RAII 守卫：确保 key_op_lock 在函数退出（含超时/错误/panic）时释放
pub struct KeyOpGuard<'a> {
    pub state: &'a AppState,
}
impl<'a> Drop for KeyOpGuard<'a> {
    fn drop(&mut self) {
        self.state.release_key_op_lock();
    }
}
