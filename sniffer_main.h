#ifndef _SNIFFER_MAIN_
#define _SNIFFER_MAIN_

#include <stdio.h>
#include <stdarg.h>

#define MAXLINE 4096

extern int main_loop();

extern void err_ret(const char *fmt, ...);
extern void err_sys(const char *fmt, ...);
extern void err_dump(const char *fmt, ...);
extern void err_msg(const char *fmt, ...);
extern void err_quit(const char *fmt, ...);
extern void	err_doit(int, int, const char *, va_list);

#endif