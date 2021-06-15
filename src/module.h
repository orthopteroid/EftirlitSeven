#ifndef _MODULE_H_
#define _MODULE_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

#define PATH_LENGTH 129

#if 0

#define LOG_INFO(id, fmt, ...) \
  pr_info("I " MOD_NAME "(%08X):%s:%d: " fmt "\n", id, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define LOG_ERR(id, fmt, ...) \
  pr_err("E " MOD_NAME "(%08X):%s:%d: " fmt "\n", id, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(id, fmt, ...) \
  pr_debug("D " MOD_NAME "(%08X):%s:%d: " fmt "\n", id, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while(false)
#endif

#else

#define LOG_INFO(id, fmt, ...) \
  printk("I " MOD_NAME "(%08X):%s:%d: " fmt "\n", id, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define LOG_ERR(id, fmt, ...) \
  printk("E " MOD_NAME "(%08X):%s:%d: " fmt "\n", id, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(id, fmt, ...) \
  printk("D " MOD_NAME "(%08X):%s:%d: " fmt "\n", id, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while(false)
#endif

#endif

bool mod_isstopping(void);

#endif // _MODULE_H_
