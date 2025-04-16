#ifndef JOURNAL_H
#define JOURNAL_H

#include <list>
#include <string>
#include <syslog.h>

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
public:
    void log(int level, const char *format, ...);
};


#endif // JOURNAL_H
