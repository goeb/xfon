#ifndef JOURNAL_H
#define JOURNAL_H

#include <list>
#include <string>
#include <syslog.h>

#include "util.h"

/* Log level, as defined in syslog.h
 *        LOG_EMERG      same as LOG_CRIT
 *        LOG_ALERT      same as LOG_CRIT
 *        LOG_CRIT       critical conditions
 *        LOG_ERR        error conditions
 *        LOG_WARNING    warning conditions
 *        LOG_NOTICE     normal, but significant, condition
 *        LOG_INFO       informational message
 *        LOG_DEBUG      debug-level message
 */
typedef int Level;

class Journal {
private:
    std::list<std::pair<Level, std::string>> lines;
    Level max_level;
public:
    Journal();
    void log(int level, const char *file, const char *func, const char *format, ...);
    void set_log_level(Level level);
    int get_log_level();
};

#define LOG(_level, _fmt, ...) do { journal.log(_level, __FILE__, __func__, _fmt, __VA_ARGS__); } while (0)
#define LOGHEX(_label, _bytes, _limit) do { journal.log(LOG_DEBUG, __FILE__, __func__, "%s: %s", _label, hexlify(_bytes, _limit).c_str()); } while (0)
#define LOGERROR(...) do { journal.log(LOG_ERR, __FILE__, __func__, __VA_ARGS__); } while (0)

extern Journal journal;

#endif // JOURNAL_H
