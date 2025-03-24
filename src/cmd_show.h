#ifndef CMD_SHOW_H
#define CMD_SHOW_H

#include <argp.h>

extern struct argp argp_show;

int cmd_show(const std::list<std::string> &certificates_paths);

#endif
