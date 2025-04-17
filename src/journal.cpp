#include <stdarg.h>

#include "journal.h"

Journal journal;

Journal::Journal()
{
    max_level = LOG_WARNING;
}

void Journal::log(int level, const char *file, const char *func, const char *format, ...)
{
    va_list ap;

    /* Determine required size. */
    va_start(ap, format);
    int n = vsnprintf(nullptr, 0, format, ap);
    va_end(ap);

    if (n < 0) return; // cannot log

    size_t size = (size_t)n + 1; // Add an extra byte for '\0'
    char *ptr = (char*)malloc(size);
    if (!ptr) return; // cannot log

    va_start(ap, format);
    n = vsnprintf(ptr, size, format, ap);
    va_end(ap);

    if (n < 0) {
        free(ptr);
        return; // cannot log
    }
    lines.push_back(std::make_pair(level, std::string(ptr)));

    if (level <= max_level) {
        if (level == LOG_DEBUG) fprintf(stderr, "%s: %s: ", file, func);
        fprintf(stderr, "%s", ptr);
        fprintf(stderr, "\n");
    }
    free(ptr);
}

void Journal::set_log_level(Level level)
{
    max_level = level;
}

int Journal::get_log_level()
{
    return max_level;
}

