#pragma once

#include "nt.h"

#include <vector>
#include <unordered_map>
#include <expected>
#include <memory>

namespace spf {

struct memory_range {
  std::uint64_t pfn = 0;
  std::size_t page_count = 0;
};

struct memory_map {
  std::vector<memory_range> ranges = {};
  std::unordered_map<void const*, std::uint64_t> translations = {};
};

enum class init_error {
  raise_privilege,
  query_ranges,
  query_pfn
};

inline bool raise_privilege() {
  BOOLEAN old = FALSE;

  if (!NT_SUCCESS(RtlAdjustPrivilege(
      SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &old)))
    return false;

  if (!NT_SUCCESS(RtlAdjustPrivilege(
      SE_DEBUG_PRIVILEGE, TRUE, FALSE, &old)))
    return false;

  return true;
}

inline NTSTATUS query_superfetch_info(
  SUPERFETCH_INFORMATION_CLASS const info_class,
  PVOID                        const buffer,
  ULONG                        const length,
  PULONG                       const return_length = nullptr
) {
  SUPERFETCH_INFORMATION superfetch_info = {
    .InfoClass = info_class,
    .Data      = buffer,
    .Length    = length
  };

  return NtQuerySystemInformation(SystemSuperfetchInformation,
    &superfetch_info, sizeof(superfetch_info), return_length);
}

inline std::vector<memory_range> query_memory_ranges_v1() {
  ULONG buffer_length = 0;

  // STATUS_BUFFER_TOO_SMALL.
  if (PF_MEMORY_RANGE_INFO_V1 info = {}; 0xC0000023 != query_superfetch_info(
      SuperfetchMemoryRangesQuery, &info, sizeof(info), &buffer_length))
    return {};

  auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
  auto const info = reinterpret_cast<PF_MEMORY_RANGE_INFO_V1*>(buffer.get());
  info->Version = 1;

  if (!NT_SUCCESS(query_superfetch_info(
      SuperfetchMemoryRangesQuery, info, buffer_length)))
    return {};

  std::vector<memory_range> ranges = {};

  for (std::uint32_t i = 0; i < info->RangeCount; ++i) {
    ranges.push_back({
      .pfn = info->Ranges[i].BasePfn,
      .page_count = info->Ranges[i].PageCount
    });
  }

  return ranges;
}

inline std::vector<memory_range> query_memory_ranges_v2() {
  ULONG buffer_length = 0;

  // STATUS_BUFFER_TOO_SMALL.
  if (PF_MEMORY_RANGE_INFO_V2 info = {}; 0xC0000023 != query_superfetch_info(
      SuperfetchMemoryRangesQuery, &info, sizeof(info), &buffer_length))
    return {};

  auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
  auto const info = reinterpret_cast<PF_MEMORY_RANGE_INFO_V2*>(buffer.get());
  info->Version = 2;

  if (!NT_SUCCESS(query_superfetch_info(
      SuperfetchMemoryRangesQuery, info, buffer_length)))
    return {};

  std::vector<memory_range> ranges = {};

  for (std::uint32_t i = 0; i < info->RangeCount; ++i) {
    ranges.push_back({
      .pfn = info->Ranges[i].BasePfn,
      .page_count = info->Ranges[i].PageCount
    });
  }

  return ranges;
}

inline std::vector<memory_range> query_memory_ranges() {
  auto ranges = query_memory_ranges_v1();
  if (ranges.empty())
    return query_memory_ranges_v2();
  return ranges;
}

// Take a snapshot of the current system memory map.
inline std::expected<memory_map, init_error> init_memory_map() {
  if (!raise_privilege())
    return std::unexpected(init_error::raise_privilege);

  memory_map mm = {
    .ranges = query_memory_ranges()
  };

  if (mm.ranges.empty())
    return std::unexpected(init_error::query_ranges);

  for (auto const& [base_pfn, page_count] : mm.ranges) {
    // This is a bit too big, but its not a big deal.
    std::size_t const buffer_length = sizeof(PF_PFN_PRIO_REQUEST) +
      sizeof(MMPFN_IDENTITY) * page_count;

    auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
    auto const request = reinterpret_cast<PF_PFN_PRIO_REQUEST*>(buffer.get());
    request->Version      = 1;
    request->RequestFlags = 1;
    request->PfnCount     = page_count;

    for (std::uint64_t i = 0; i < page_count; ++i)
      request->PageData[i].PageFrameIndex = base_pfn + i;

    if (!NT_SUCCESS(query_superfetch_info(
        SuperfetchPfnQuery, request, buffer_length)))
      return std::unexpected(init_error::query_pfn);

    for (std::uint64_t i = 0; i < page_count; ++i) {
      // Cache the translation for this page.
      if (void const* const virt = request->PageData[i].u2.VirtualAddress)
        mm.translations[virt] = (base_pfn + i) << 12;
    }
  }

  return mm;
}

// Translate a virtual address to a physical address.
inline std::uint64_t translate(memory_map const& mm, void const* const addr) {
  // Align to the lowest page boundary.
  void const* const aligned = reinterpret_cast<void const*>(
    reinterpret_cast<std::uint64_t>(addr) & ~0xFFFull);

  auto const it = mm.translations.find(aligned);
  if (it == end(mm.translations))
    return 0;

  return it->second + (reinterpret_cast<std::uint64_t>(addr) & 0xFFF);
}

} // spf
