#define _NO_CRT_STDIO_INLINE
#include <ntifs.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include "Log.h"

void LogPrint(__log_type Type, const char* fmt, ...)
{
	char* LogType;
	LARGE_INTEGER SystemTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS TimeFields;
	char TimeBuffer[20] = {};
	char MessageBuffer[412] = {};
	char OutputBuffer[512] = {};
	va_list Args = {};

	switch (Type)
	{
		case LOG_TYPE_DEBUG:
		{
			LogType = "[DEBUG]";
			break;
		}
		case LOG_TYPE_DUMP:
		{
			LogType = "[DUMP]";
			break;
		}
		case LOG_TYPE_ERROR:
		{
			LogType = "[ERROR]";
			break;
		}
		case LOG_TYPE_INFO:
		{
			LogType = "[INFORMATION]";
			break;
		}
		default:
		{
			LogType = "[UNKNOWN]";
			break;
		}

	}

	KeQuerySystemTime(&SystemTime);
	ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
	RtlTimeToTimeFields(&LocalTime, &TimeFields);

	RtlStringCchPrintfA(
		TimeBuffer,
		sizeof(TimeBuffer),
		"[%02hd:%02hd:%02hd.%03hd]",
		TimeFields.Hour,
		TimeFields.Minute,
		TimeFields.Second,
		TimeFields.Milliseconds);

	va_start(Args, fmt);
	RtlStringCchVPrintfA(MessageBuffer, sizeof(MessageBuffer), fmt, Args);
	va_end(Args);

	char* OutputFormat = "%s  %s  %s\r\n";

	RtlStringCchPrintfA(
		OutputBuffer,
		sizeof(OutputBuffer),
		OutputFormat,
		TimeBuffer,
		LogType,
		MessageBuffer);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", OutputBuffer);
}