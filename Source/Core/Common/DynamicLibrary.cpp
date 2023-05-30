// Copyright 2019 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Common/DynamicLibrary.h"

#include <cstring>

#include <fmt/format.h>

#include "Common/Assert.h"

#if defined(_WIN32)
#include <Windows.h>
#elif defined(__SWITCH__)
// TODO
#else
#include <dlfcn.h>
#endif

namespace Common
{
DynamicLibrary::DynamicLibrary() = default;

DynamicLibrary::DynamicLibrary(const char* filename)
{
  Open(filename);
}

DynamicLibrary::~DynamicLibrary()
{
  Close();
}

std::string DynamicLibrary::GetUnprefixedFilename(const char* filename)
{
#if defined(_WIN32)
  return std::string(filename) + ".dll";
#elif defined(__APPLE__)
  return std::string(filename) + ".dylib";
#elif defined(__SWITCH__)
  return std::string(filename) + ".nro";
#else
  return std::string(filename) + ".so";
#endif
}

std::string DynamicLibrary::GetVersionedFilename(const char* libname, int major, int minor)
{
#if defined(_WIN32)
  if (major >= 0 && minor >= 0)
    return fmt::format("{}-{}-{}.dll", libname, major, minor);
  else if (major >= 0)
    return fmt::format("{}-{}.dll", libname, major);
  else
    return fmt::format("{}.dll", libname);
#elif defined(__APPLE__)
  const char* prefix = std::strncmp(libname, "lib", 3) ? "lib" : "";
  if (major >= 0 && minor >= 0)
    return fmt::format("{}{}.{}.{}.dylib", prefix, libname, major, minor);
  else if (major >= 0)
    return fmt::format("{}{}.{}.dylib", prefix, libname, major);
  else
    return fmt::format("{}{}.dylib", prefix, libname);
#elif defined(__SWITCH__)
  return fmt::format("{}.nro", libname);
#else
  const char* prefix = std::strncmp(libname, "lib", 3) ? "lib" : "";
  if (major >= 0 && minor >= 0)
    return fmt::format("{}{}.so.{}.{}", prefix, libname, major, minor);
  else if (major >= 0)
    return fmt::format("{}{}.so.{}", prefix, libname, major);
  else
    return fmt::format("{}{}.so", prefix, libname);
#endif
}

bool DynamicLibrary::Open(const char* filename)
{
#if defined(_WIN32)
  m_handle = reinterpret_cast<void*>(LoadLibraryA(filename));
#elif defined(__SWITCH__)
  // TODO
  m_handle = nullptr;
#else
  m_handle = dlopen(filename, RTLD_NOW);
#endif
  return m_handle != nullptr;
}

void DynamicLibrary::Close()
{
  if (!IsOpen())
    return;

#if defined(_WIN32)
  FreeLibrary(reinterpret_cast<HMODULE>(m_handle));
#elif defined(__SWITCH__)
    // TODO
#else
  dlclose(m_handle);
#endif
  m_handle = nullptr;
}

void* DynamicLibrary::GetSymbolAddress(const char* name) const
{
#if defined(_WIN32)
  return reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(m_handle), name));
#elif defined(__SWITCH__)
  // TODO
  return nullptr;
#else
  return reinterpret_cast<void*>(dlsym(m_handle, name));
#endif
}
}  // namespace Common
