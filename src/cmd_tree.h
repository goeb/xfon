#ifndef CMD_TREE_H
#define CMD_TREE_H

#include <argp.h>
#include <string>
#include <list>

extern struct argp argp_tree;

int cmd_tree(const std::list<std::string> &certificates_paths);

#endif
