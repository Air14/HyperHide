#pragma once
#define LogError(format, ...)  \
    LogPrint(LOG_TYPE_ERROR," [%s:%d] " format , __func__, __LINE__, __VA_ARGS__)
#define LogDebug(format, ...)  \
    LogPrint(LOG_TYPE_DEBUG," [%s:%d] " format , __func__, __LINE__, __VA_ARGS__)
#define LogDump(format, ...)  \
    LogPrint(LOG_TYPE_DUMP," [%s:%d] " format , __func__, __LINE__, __VA_ARGS__)
#define LogInfo(format, ...)  \
    LogPrint(LOG_TYPE_INFO," [%s:%d] " format , __func__, __LINE__, __VA_ARGS__)

enum __log_type
{
	LOG_TYPE_DEBUG,
	LOG_TYPE_ERROR,
	LOG_TYPE_DUMP,
	LOG_TYPE_INFO
};

void LogPrint(__log_type type, const char* fmt, ...);