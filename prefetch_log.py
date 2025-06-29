#!/usr/bin/env python3
"""
Prefetch Full Execution Log Extractor
Extracts ALL execution times from Windows Prefetch files
Supports Windows 11 MAM compressed files
"""

import os
import sys
import struct
import ctypes
import datetime
import argparse
from pathlib import Path
from collections import defaultdict, Counter
import csv

# Check if running with admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("WARNING: Running without admin privileges may limit access to some files.")
    print("For best results, run as Administrator.\n")

# ANSI color codes
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    
    @staticmethod
    def enable_windows_ansi():
        """Enable ANSI color codes on Windows"""
        if sys.platform == 'win32':
            try:
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                pass

def decompress_mam(data: bytes) -> bytes:
    """Decompress MAM compressed prefetch files for Windows 11"""
    if data[:3] != b'MAM':
        return data
        
    mam_version = data[3]
    uncompressed_size = struct.unpack('<I', data[4:8])[0]
    
    if uncompressed_size == 0 or uncompressed_size > 100 * 1024 * 1024:
        return None
        
    compressed_data = data[8:]
    
    # Windows 11 uses XPRESS Huffman compression
    COMPRESSION_FORMAT_XPRESS_HUFF = 4
    
    try:
        ntdll = ctypes.windll.ntdll
        
        if not hasattr(ntdll, 'RtlDecompressBufferEx'):
            return None
        
        # Get workspace size
        workspace_size = ctypes.c_ulong()
        compress_workspace_size = ctypes.c_ulong()
        
        result = ntdll.RtlGetCompressionWorkSpaceSize(
            COMPRESSION_FORMAT_XPRESS_HUFF,
            ctypes.byref(workspace_size),
            ctypes.byref(compress_workspace_size)
        )
        
        if result != 0:
            return None
        
        # Allocate workspace
        workspace = None
        if workspace_size.value > 0:
            workspace = ctypes.create_string_buffer(workspace_size.value)
        
        # Allocate output buffer
        output = ctypes.create_string_buffer(uncompressed_size)
        final_size = ctypes.c_ulong()
        
        # Create compressed data buffer
        compressed_buffer = (ctypes.c_ubyte * len(compressed_data)).from_buffer_copy(compressed_data)
        
        # Decompress
        result = ntdll.RtlDecompressBufferEx(
            COMPRESSION_FORMAT_XPRESS_HUFF,
            output,
            uncompressed_size,
            compressed_buffer,
            len(compressed_data),
            ctypes.byref(final_size),
            workspace
        )
        
        if result == 0:  # STATUS_SUCCESS
            return bytes(output.raw[:final_size.value])
    except Exception as e:
        print(f"MAM decompression error: {e}")
    
    return None

def parse_prefetch_file(file_path: str, verbose: bool = False) -> list:
    """Parse a single prefetch file and extract all execution times"""
    executions = []
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_info = os.stat(file_path)
        exe_name = os.path.basename(file_path).split('-')[0]
        
        # Check if compressed
        if data[:3] == b'MAM':
            if verbose:
                print(f"  Decompressing MAM file: {os.path.basename(file_path)}")
            decompressed = decompress_mam(data)
            if decompressed:
                data = decompressed
            else:
                # Fallback to file timestamp
                mod_time = datetime.datetime.fromtimestamp(file_info.st_mtime)
                executions.append({
                    'ProcessName': exe_name,
                    'ExecutionTime': mod_time,
                    'PrefetchFile': os.path.basename(file_path),
                    'FileSize': file_info.st_size,
                    'Slot': 0,  # 0 indicates fallback
                    'Source': 'File Modified Time (MAM decompression failed)'
                })
                return executions
        
        # Parse version
        if len(data) >= 4:
            version = struct.unpack('<I', data[:4])[0]
        else:
            return executions
        
        # Offset mappings for different Windows versions
        offset_mappings = {
            0x1A: [0x78, 0x80],           # Windows 7
            0x17: [0x80],                 # Windows 8  
            0x1E: [0x80, 0x98],          # Windows 10 (older)
            0x1F: [0x80, 0x98, 0xD0],    # Windows 10/11
            0x20: [0x80, 0x98, 0xB0],    # Windows 10 (recent)
            0x21: [0x80, 0xD0, 0x98],    # Windows 11
            0x22: [0x80, 0xD0, 0x98],    # Windows 11 (newer)
            0x23: [0x80, 0xD0, 0x98],    # Windows 11 (newest)
            0x24: [0x80, 0xD0, 0x98],    # Windows 11 (24H2)
        }
        
        # Determine offsets to try
        offsets_to_try = []
        if version in offset_mappings:
            offsets_to_try.extend(offset_mappings[version])
        
        # Add common offsets as fallback
        offsets_to_try.extend([0x80, 0xD0, 0x98, 0x90, 0xC8, 0x78, 0xB0])
        offsets_to_try = list(dict.fromkeys(offsets_to_try))
        
        found_valid = False
        
        for offset in offsets_to_try:
            if offset + 64 > len(data):
                continue
                
            # Read up to 8 timestamps
            valid_count = 0
            
            for i in range(8):
                ft_offset = offset + (i * 8)
                if ft_offset + 8 > len(data):
                    break
                    
                ft = struct.unpack('<Q', data[ft_offset:ft_offset+8])[0]
                
                # Skip invalid values
                if ft == 0 or ft == 0xFFFFFFFFFFFFFFFF:
                    continue
                    
                # Validate range (1990-2030)
                if ft < 116444736000000000 or ft > 159725856000000000:
                    continue
                    
                try:
                    # Convert FILETIME to datetime
                    run_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft/10)
                    
                    if run_time.year < 1990 or run_time.year > 2030:
                        continue
                        
                    valid_count += 1
                    
                    executions.append({
                        'ProcessName': exe_name,
                        'ExecutionTime': run_time,
                        'PrefetchFile': os.path.basename(file_path),
                        'FileSize': file_info.st_size,
                        'Slot': i + 1,
                        'Source': f'Prefetch (Offset: 0x{offset:X}, Slot: {i+1})'
                    })
                    
                except:
                    continue
                    
            if valid_count > 0:
                found_valid = True
                break
                
        # If no valid timestamps found, use file timestamp
        if not found_valid:
            mod_time = datetime.datetime.fromtimestamp(file_info.st_mtime)
            executions.append({
                'ProcessName': exe_name,
                'ExecutionTime': mod_time,
                'PrefetchFile': os.path.basename(file_path),
                'FileSize': file_info.st_size,
                'Slot': 0,
                'Source': 'File Modified Time (No valid timestamps found)'
            })
                
    except Exception as e:
        if verbose:
            print(f"Error parsing {file_path}: {e}")
            
    return executions

def format_size(bytes):
    """Format bytes to human readable size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.1f}{unit}"
        bytes /= 1024.0
    return f"{bytes:.1f}TB"

def main():
    Color.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(description='Extract full execution history from Windows Prefetch files')
    parser.add_argument('--path', default=r'C:\Windows\Prefetch',
                      help='Prefetch directory path (default: C:\\Windows\\Prefetch)')
    parser.add_argument('--output', help='Output CSV file path')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Verbose output')
    parser.add_argument('--days', type=int, default=0,
                      help='Only show executions from last N days (0 = all)')
    parser.add_argument('--process', help='Filter by process name (partial match)')
    parser.add_argument('--summary', action='store_true',
                      help='Show summary statistics only')
    parser.add_argument('--limit', type=int, default=0,
                      help='Limit detailed output to N most recent executions (0 = all)')
    parser.add_argument('--sort', choices=['time', 'process', 'size'], default='time',
                      help='Sort executions by time, process name, or file size (default: time)')
    parser.add_argument('--suspicious', action='store_true',
                      help='Show only suspicious processes')
    parser.add_argument('--start', help='Start date filter (YYYY-MM-DD)')
    parser.add_argument('--end', help='End date filter (YYYY-MM-DD)')
    parser.add_argument('--group', action='store_true',
                      help='Group executions by date')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"{Color.RED}Error: Prefetch directory not found: {args.path}{Color.RESET}")
        sys.exit(1)
    
    print(f"{Color.CYAN}=== Prefetch Full Execution Log Extractor ==={Color.RESET}")
    print(f"Prefetch directory: {args.path}")
    print(f"Scanning prefetch files...\n")
    
    # Get all prefetch files
    pf_files = list(Path(args.path).glob("*.pf"))
    print(f"Found {Color.GREEN}{len(pf_files)}{Color.RESET} prefetch files")
    
    # Parse all files
    all_executions = []
    mam_count = 0
    parsed_count = 0
    failed_count = 0
    
    print("Parsing prefetch files...")
    for i, pf_file in enumerate(pf_files, 1):
        # Show progress
        if i % 50 == 0 or i == len(pf_files):
            print(f"  Progress: {i}/{len(pf_files)} files processed...", end='\r')
        
        # Check if MAM
        with open(pf_file, 'rb') as f:
            if f.read(3) == b'MAM':
                mam_count += 1
        
        executions = parse_prefetch_file(str(pf_file), args.verbose)
        if executions:
            all_executions.extend(executions)
            parsed_count += 1
        else:
            failed_count += 1
    
    print(f"\n{Color.GREEN}Parsing complete!{Color.RESET}                    ")  # Clear progress line
    
    print(f"MAM compressed files: {Color.YELLOW}{mam_count}{Color.RESET}")
    print(f"Successfully parsed: {Color.GREEN}{parsed_count}{Color.RESET}")
    print(f"Failed to parse: {Color.RED}{failed_count}{Color.RESET}")
    print(f"Total executions found: {Color.GREEN}{len(all_executions)}{Color.RESET}\n")
    
    if not all_executions:
        print(f"{Color.RED}No execution data found!{Color.RESET}")
        sys.exit(0)
    
    # Apply filters
    if args.days > 0:
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=args.days)
        all_executions = [e for e in all_executions if e['ExecutionTime'] >= cutoff_date]
        print(f"Filtered to last {args.days} days: {Color.GREEN}{len(all_executions)}{Color.RESET} executions")
    
    if args.start:
        try:
            start_date = datetime.datetime.strptime(args.start, '%Y-%m-%d')
            all_executions = [e for e in all_executions if e['ExecutionTime'] >= start_date]
            print(f"Filtered from {args.start}: {Color.GREEN}{len(all_executions)}{Color.RESET} executions")
        except ValueError:
            print(f"{Color.RED}Invalid start date format. Use YYYY-MM-DD{Color.RESET}")
    
    if args.end:
        try:
            end_date = datetime.datetime.strptime(args.end, '%Y-%m-%d') + datetime.timedelta(days=1)
            all_executions = [e for e in all_executions if e['ExecutionTime'] < end_date]
            print(f"Filtered until {args.end}: {Color.GREEN}{len(all_executions)}{Color.RESET} executions")
        except ValueError:
            print(f"{Color.RED}Invalid end date format. Use YYYY-MM-DD{Color.RESET}")
    
    if args.process:
        all_executions = [e for e in all_executions if args.process.lower() in e['ProcessName'].lower()]
        print(f"Filtered by process '{args.process}': {Color.GREEN}{len(all_executions)}{Color.RESET} executions")
    
    if args.suspicious:
        suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
                               'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'certutil.exe',
                               'bitsadmin.exe', 'msiexec.exe', 'wusa.exe']
        all_executions = [e for e in all_executions 
                         if any(s in e['ProcessName'].lower() for s in suspicious_processes)]
        print(f"Filtered to suspicious processes: {Color.RED}{len(all_executions)}{Color.RESET} executions")
    
    if all_executions:
        print()  # Add blank line after filters
    
    # Sort executions
    if args.sort == 'time':
        all_executions.sort(key=lambda x: x['ExecutionTime'], reverse=True)
    elif args.sort == 'process':
        all_executions.sort(key=lambda x: (x['ProcessName'].lower(), x['ExecutionTime']), reverse=True)
    elif args.sort == 'size':
        all_executions.sort(key=lambda x: x['FileSize'], reverse=True)
    
    # Summary statistics
    if all_executions:
        print(f"{Color.YELLOW}=== Summary Statistics ==={Color.RESET}")
        
        # Time range
        earliest = min(e['ExecutionTime'] for e in all_executions)
        latest = max(e['ExecutionTime'] for e in all_executions)
        print(f"Time range: {earliest.strftime('%Y-%m-%d %H:%M:%S')} to {latest.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration: {(latest - earliest).days} days\n")
        
        # Process statistics
        process_counts = Counter(e['ProcessName'] for e in all_executions)
        print(f"Unique processes: {Color.GREEN}{len(process_counts)}{Color.RESET}")
        print(f"\nTop 20 most executed processes:")
        print("-" * 50)
        for process, count in process_counts.most_common(20):
            print(f"{process:<40} {count:>5} executions")
        
        # Hourly distribution
        hour_counts = Counter(e['ExecutionTime'].hour for e in all_executions)
        print(f"\n{Color.YELLOW}Hourly Activity Distribution:{Color.RESET}")
        for hour in range(24):
            count = hour_counts.get(hour, 0)
            bar = '█' * int(count * 50 / max(hour_counts.values())) if hour_counts else ''
            print(f"{hour:02d}:00 {count:>5} {Color.BLUE}{bar}{Color.RESET}")
        
        # Daily distribution
        daily_counts = defaultdict(int)
        for e in all_executions:
            daily_counts[e['ExecutionTime'].date()] += 1
        
        print(f"\n{Color.YELLOW}Top 20 Most Active Days:{Color.RESET}")
        print("-" * 50)
        for date, count in sorted(daily_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"{date} - {count} executions")
    
    # Detailed timeline (if not summary only)
    if not args.summary and all_executions:
        print(f"\n{Color.YELLOW}=== Detailed Execution Timeline ==={Color.RESET}")
        
        # Apply limit if specified
        display_executions = all_executions
        if args.limit > 0:
            display_executions = all_executions[:args.limit]
            print(f"(Showing {args.limit} most recent of {len(all_executions)} total executions)")
        else:
            print(f"(Showing ALL {len(all_executions)} executions)")
        
        if args.group:
            # Group by date
            date_groups = defaultdict(list)
            for e in display_executions:
                date_groups[e['ExecutionTime'].date()].append(e)
            
            for date in sorted(date_groups.keys(), reverse=True):
                print(f"\n{Color.CYAN}=== {date} ({len(date_groups[date])} executions) ==={Color.RESET}")
                print("-" * 120)
                print(f"{'Time':<20} {'Process':<30} {'Size':<10} {'Prefetch File':<35} {'Source':<25}")
                print("-" * 120)
                
                for e in sorted(date_groups[date], key=lambda x: x['ExecutionTime'], reverse=True):
                    time_str = e['ExecutionTime'].strftime('%H:%M:%S')
                    size_str = format_size(e['FileSize'])
                    source_str = e['Source'][:25]
                    
                    # Highlight suspicious processes
                    suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
                                           'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'certutil.exe',
                                           'bitsadmin.exe', 'msiexec.exe', 'wusa.exe']
                    color = Color.RED if any(s in e['ProcessName'].lower() for s in suspicious_processes) else Color.RESET
                    
                    print(f"{time_str:<20} {color}{e['ProcessName']:<30}{Color.RESET} "
                          f"{size_str:<10} {e['PrefetchFile']:<35} {source_str:<25}")
        else:
            # Regular timeline
            print("-" * 120)
            print(f"{'Time':<20} {'Process':<30} {'Size':<10} {'Prefetch File':<35} {'Source':<25}")
            print("-" * 120)
            
            for e in display_executions:
                time_str = e['ExecutionTime'].strftime('%Y-%m-%d %H:%M:%S')
                size_str = format_size(e['FileSize'])
                source_str = e['Source'][:25]
                
                # Highlight suspicious processes
                suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
                                       'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'certutil.exe',
                                       'bitsadmin.exe', 'msiexec.exe', 'wusa.exe']
                color = Color.RED if any(s in e['ProcessName'].lower() for s in suspicious_processes) else Color.RESET
                
                print(f"{time_str:<20} {color}{e['ProcessName']:<30}{Color.RESET} "
                      f"{size_str:<10} {e['PrefetchFile']:<35} {source_str:<25}")
    
    # Export to CSV if requested
    if args.output:
        with open(args.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['ExecutionTime', 'ProcessName', 
                                                  'PrefetchFile', 'FileSize', 'Slot', 'Source'])
            writer.writeheader()
            for e in all_executions:
                writer.writerow({
                    'ExecutionTime': e['ExecutionTime'].strftime('%Y-%m-%d %H:%M:%S'),
                    'ProcessName': e['ProcessName'],
                    'PrefetchFile': e['PrefetchFile'],
                    'FileSize': e['FileSize'],
                    'Slot': e['Slot'],
                    'Source': e['Source']
                })
        print(f"\n{Color.GREEN}Execution log exported to: {args.output}{Color.RESET}")
    
    print(f"\n{Color.CYAN}=== Analysis Complete ==={Color.RESET}")

if __name__ == "__main__":
    main()
