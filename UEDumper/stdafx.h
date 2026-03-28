#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <filesystem>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <set>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <chrono>
#include <ctime>
#include <string>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <cstdint>
#include <cwchar>
#include <locale>
#include <algorithm>
#include <ranges>

#ifdef UEDUMPER_HEADLESS
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <unistd.h>

using BYTE = unsigned char;
using WORD = uint16_t;
using DWORD = uint32_t;
using DWORD64 = uint64_t;
using BOOL = int;
using BOOLEAN = unsigned char;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef FORCEINLINE
#define FORCEINLINE inline __attribute__((always_inline))
#endif

struct ImVec2
{
    float x;
    float y;

    constexpr ImVec2(float _x = 0.0f, float _y = 0.0f) : x(_x), y(_y) {}
};

inline void DebugBreak()
{
    raise(SIGTRAP);
}

inline int localtime_s(std::tm* out, const std::time_t* in)
{
    return localtime_r(in, out) ? 0 : errno;
}

inline int strcpy_s(char* dest, size_t destsz, const char* src)
{
    if (!dest || !src || destsz == 0)
        return EINVAL;

    const auto len = std::strlen(src);
    if (len + 1 > destsz)
        return ERANGE;

    std::memcpy(dest, src, len + 1);
    return 0;
}

inline int sprintf_s(char* buffer, size_t sizeOfBuffer, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    const int result = std::vsnprintf(buffer, sizeOfBuffer, format, args);
    va_end(args);
    return result;
}

inline int sprintf_s(char* buffer, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    const int result = std::vsprintf(buffer, format, args);
    va_end(args);
    return result;
}

inline int vsprintf_s(char* buffer, size_t sizeOfBuffer, const char* format, va_list args)
{
    return std::vsnprintf(buffer, sizeOfBuffer, format, args);
}

#else
/// Windows APIS
#include <Windows.h>

/// ImGui related
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <d3d11.h>
#endif

//third party
#include <json.hpp>
#include <AES.h>
