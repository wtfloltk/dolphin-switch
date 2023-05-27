// Copyright 2008 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Common/MemArena.h"

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>

#include <fmt/format.h>

#include <switch.h>

#include "Common/CommonFuncs.h"
#include "Common/CommonTypes.h"
#include "Common/Logging/Log.h"
#include "Common/MsgHandler.h"
#include "Common/StringUtil.h"

namespace Common
{

struct SwitchViewInfo
{
  VirtmemReservation* resv;
  s64 offset;
  size_t size;
};

struct SwitchMapInfo
{
  s64 offset;
  size_t size;
};

MemArena::MemArena()
{
  u64 value = 0;
  svcGetInfo(&value, (InfoType)65001, INVALID_HANDLE, 0);
  m_cur_proc_handle = (Handle)value;
}

MemArena::~MemArena()
{
  // svcCloseHandle(m_cur_proc_handle);
}

void MemArena::GrabSHMSegment(size_t size, std::string_view base_name)
{
  Result r;

  void* mem = aligned_alloc(0x1000, size);
  PanicAlertFmt("GrabSHMSegment: size: 0x{:08X}, m_memory: {}, name: {}\n", size, mem, base_name);

  virtmemLock();
  m_memory = virtmemFindCodeMemory(size, 0x1000);

  r = svcMapProcessCodeMemory(m_cur_proc_handle, (u64)m_memory, (u64)mem, size);
  PanicAlertFmt("svcMapProcessCodeMemory: 0x{:X}\n", r);

  r = svcSetProcessMemoryPermission(m_cur_proc_handle, (u64)m_memory, size, Perm_Rw);
  PanicAlertFmt("svcSetProcessMemoryPermission: 0x{:X}\n", r);

  virtmemUnlock();
}

void MemArena::ReleaseSHMSegment()
{
  free(m_memory);
}

void* MemArena::CreateView(s64 offset, size_t size)
{
  virtmemLock();
  void* view = virtmemFindAslr(size, 0x1000);
  VirtmemReservation* resv = virtmemAddReservation(view, size);
  virtmemUnlock();

  PanicAlertFmt("CreateView: offset: 0x{:08X}, size: 0x{:08X}\n", offset, size);
  PanicAlertFmt("virtmemFindAslr: 0x{}\n", view);

  PanicAlertFmt("InfoType_MesosphereCurrentProcess: 0x{:08X}\n", m_cur_proc_handle);

  Result r = svcMapProcessMemory(view, m_cur_proc_handle, (u64)m_memory + offset, size);
  PanicAlertFmt("svcMapProcessMemory called with 0x{:08X}, returned: 0x{:08X}\n",
                (u64)m_memory + offset, r);

  if (R_FAILED(r))
  {
    virtmemLock();
    virtmemRemoveReservation(resv);
    virtmemUnlock();
    return nullptr;
  }

  m_views[view] = {resv, offset, size};

  return view;
}

void MemArena::ReleaseView(void* view, size_t size)
{
  SwitchViewInfo info = m_views[view];
  svcUnmapProcessMemory(view, m_cur_proc_handle, (u64)m_memory + info.offset, info.size);
  virtmemLock();
  virtmemRemoveReservation(info.resv);
  virtmemUnlock();
  m_views.erase(view);
}

u8* MemArena::ReserveMemoryRegion(size_t memory_size)
{
  virtmemLock();
  void* dst = virtmemFindAslr(memory_size, 0x1000);
  m_virtmem_resv = virtmemAddReservation(m_memory, memory_size);
  virtmemUnlock();

  PanicAlertFmt("ReserveMemoryRegion: {}\n", dst);

  return (u8*)dst;
}

void MemArena::ReleaseMemoryRegion()
{
  virtmemLock();
  virtmemRemoveReservation(m_virtmem_resv);
  virtmemUnlock();
}

void* MemArena::MapInMemoryRegion(s64 offset, size_t size, void* base)
{
  Result r = svcMapProcessMemory(base, m_cur_proc_handle, (u64)m_memory + offset, size);
  if (R_FAILED(r))
    return nullptr;

  m_maps[base] = {offset, size};

  return base;
}

void MemArena::UnmapFromMemoryRegion(void* view, size_t size)
{
  SwitchMapInfo map = m_maps[view];
  svcUnmapProcessMemory(view, m_cur_proc_handle, (u64)m_memory + map.offset, map.size);
  m_views.erase(view);
}
}  // namespace Common
