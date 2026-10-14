// SPDX-License-Identifier: PolyForm-Shield-1.0.0
#include <stdint.h>
int varsto_start(const char *home_dir, uint16_t port);
char *varsto_url(void);
char *varsto_token(void);
void varsto_free(char *s);
// One line into the core log (<home>/logs/varsto-ffi-ios.log, module "app").
// level: 1 error, 2 warn, 3 info, 4 debug, 5 trace. Ignored before varsto_start.
void varsto_log(int level, const char *msg);
