#!/usr/bin/env python3
"""
Advanced Prefetch Forensic Analyzer
Extracts ALL forensic information from Windows Prefetch files
Including file references, directories, volumes, DLLs, and more
"""

import os
import sys
import struct
import ctypes
import datetime
import argparse
import json
from pathlib import Path
from collections import defaultdict, Counter

# Check if running with admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("WARNING: Running without admin privileges may limit access to some files.")
    print("For best results, run as Administrator.\n")

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
        if sys.platform == 'win32':
            try:
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                pass

class PrefetchForensics:
    """Extract all forensic data from prefetch files"""
    
    def __init__(self, file_path, verbose=False):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)  # Define this first
        self.data = None
        self.decompressed = False
        self.verbose = verbose
        self.forensic_data = {
            'file_path': file_path,
            'file_name': self.file_name,
            'process_name': self.file_name.split('-')[0],
            'hash': None,
            'file_size': os.path.getsize(file_path),
            'created': datetime.datetime.fromtimestamp(os.path.getctime(file_path)),
            'modified': datetime.datetime.fromtimestamp(os.path.getmtime(file_path)),
            'version': None,
            'signature': None,
            'execution_count': 0,
            'execution_times': [],
            'last_execution': None,
            'volumes': [],
            'directories': [],
            'files_accessed': [],
            'file_metrics': {},
            'trace_chains': [],
            'loaded_dlls': [],
            'mam_compressed': False,
            'parsing_errors': []
        }
        
        # Extract hash from filename
        if '-' in self.file_name:
            self.forensic_data['hash'] = self.file_name.split('-')[1].split('.')[0]
    
    def decompress_mam(self, data):
        """Decompress MAM compressed prefetch files"""
        if data[:3] != b'MAM':
            return data
            
        self.forensic_data['mam_compressed'] = True
        mam_version = data[3]
        uncompressed_size = struct.unpack('<I', data[4:8])[0]
        
        if self.verbose:
            print(f"\n  MAM version: 0x{mam_version:02X}, uncompressed size: {uncompressed_size}")
        
        if uncompressed_size == 0 or uncompressed_size > 100 * 1024 * 1024:
            return None
            
        compressed_data = data[8:]
        COMPRESSION_FORMAT_XPRESS_HUFF = 4
        
        try:
            ntdll = ctypes.windll.ntdll
            
            if not hasattr(ntdll, 'RtlDecompressBufferEx'):
                return None
            
            workspace_size = ctypes.c_ulong()
            compress_workspace_size = ctypes.c_ulong()
            
            result = ntdll.RtlGetCompressionWorkSpaceSize(
                COMPRESSION_FORMAT_XPRESS_HUFF,
                ctypes.byref(workspace_size),
                ctypes.byref(compress_workspace_size)
            )
            
            if result != 0:
                return None
            
            workspace = None
            if workspace_size.value > 0:
                workspace = ctypes.create_string_buffer(workspace_size.value)
            
            output = ctypes.create_string_buffer(uncompressed_size)
            final_size = ctypes.c_ulong()
            compressed_buffer = (ctypes.c_ubyte * len(compressed_data)).from_buffer_copy(compressed_data)
            
            result = ntdll.RtlDecompressBufferEx(
                COMPRESSION_FORMAT_XPRESS_HUFF,
                output,
                uncompressed_size,
                compressed_buffer,
                len(compressed_data),
                ctypes.byref(final_size),
                workspace
            )
            
            if result == 0:
                self.decompressed = True
                return bytes(output.raw[:final_size.value])
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"MAM decompression error: {str(e)}")
        
        return None
    
    def parse_file_information_array(self, offset, num_entries, string_offset):
        """Parse file information array (26, 30, or 34 bytes per entry)"""
        files = []
        
        # Determine entry size based on version
        if self.forensic_data['version'] == 0x17:  # Win8
            entry_size = 26
        elif self.forensic_data['version'] in [0x1A, 0x1E]:  # Win8.1/10
            entry_size = 30
        else:  # Win10/11
            entry_size = 34
            
        try:
            for i in range(num_entries):
                entry_offset = offset + (i * entry_size)
                if entry_offset + entry_size > len(self.data):
                    break
                    
                # Parse metrics
                metrics = struct.unpack('<IIIBB', self.data[entry_offset:entry_offset+18])
                
                # Parse filename offset and length
                if entry_size >= 30:
                    fn_offset = struct.unpack('<I', self.data[entry_offset+18:entry_offset+22])[0]
                    fn_length = struct.unpack('<I', self.data[entry_offset+22:entry_offset+26])[0]
                else:
                    fn_offset = struct.unpack('<H', self.data[entry_offset+18:entry_offset+20])[0]
                    fn_length = struct.unpack('<H', self.data[entry_offset+20:entry_offset+22])[0]
                
                # Get filename
                if string_offset + fn_offset + fn_length*2 <= len(self.data):
                    filename_data = self.data[string_offset + fn_offset:string_offset + fn_offset + fn_length*2]
                    filename = filename_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                    
                    if filename:
                        file_info = {
                            'filename': filename,
                            'prefetch_count': metrics[1],
                            'fetch_count': metrics[2],
                            'flags': metrics[4]
                        }
                        files.append(file_info)
                        
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"File parsing error: {str(e)}")
            
        return files
    
    def parse_volume_information(self, offset, count):
        """Parse volume information blocks"""
        volumes = []
        
        try:
            current_offset = offset
            for i in range(count):
                if current_offset + 104 > len(self.data):
                    break
                    
                # Volume path offset and length
                vol_path_offset = struct.unpack('<I', self.data[current_offset:current_offset+4])[0]
                vol_path_length = struct.unpack('<I', self.data[current_offset+4:current_offset+8])[0]
                
                # Volume creation time
                vol_create_time = struct.unpack('<Q', self.data[current_offset+8:current_offset+16])[0]
                
                # Volume serial number
                vol_serial = struct.unpack('<I', self.data[current_offset+16:current_offset+20])[0]
                
                # Get volume path
                if current_offset + vol_path_offset + vol_path_length*2 <= len(self.data):
                    vol_path_data = self.data[current_offset + vol_path_offset:current_offset + vol_path_offset + vol_path_length*2]
                    vol_path = vol_path_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                    
                    # Convert creation time
                    create_dt = None
                    if vol_create_time > 0:
                        try:
                            create_dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=vol_create_time/10)
                        except:
                            pass
                    
                    volume_info = {
                        'path': vol_path,
                        'creation_time': create_dt.isoformat() if create_dt else None,
                        'serial_number': f"{vol_serial:08X}",
                        'offset': current_offset
                    }
                    volumes.append(volume_info)
                
                # Move to next volume (size varies by version)
                if self.forensic_data['version'] >= 0x1A:
                    current_offset += 104
                else:
                    current_offset += 40
                    
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"Volume parsing error: {str(e)}")
            
        return volumes
    
    def parse_trace_chains(self, offset, count):
        """Parse trace chain array (memory page information)"""
        chains = []
        
        try:
            # 12 bytes per entry (next index, block count, flags/sample)
            for i in range(min(count, 100)):  # Limit to first 100
                entry_offset = offset + (i * 12)
                if entry_offset + 12 > len(self.data):
                    break
                    
                next_index = struct.unpack('<I', self.data[entry_offset:entry_offset+4])[0]
                block_count = struct.unpack('<I', self.data[entry_offset+4:entry_offset+8])[0]
                flags = struct.unpack('<B', self.data[entry_offset+8:entry_offset+9])[0]
                
                if block_count > 0:
                    chains.append({
                        'index': i,
                        'next_index': next_index,
                        'block_count': block_count,
                        'flags': flags
                    })
                    
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"Trace chain parsing error: {str(e)}")
            
        return chains
    
    def parse(self):
        """Parse all forensic data from the prefetch file"""
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()
            
            # Check signature
            if len(self.data) < 8:
                self.forensic_data['parsing_errors'].append("File too small")
                return self.forensic_data
            
            # Check if compressed
            if self.data[:3] == b'MAM':
                if self.verbose:
                    print(f"\n  File: {self.file_name}")
                    print(f"  Compressed: Yes (MAM)")
                decompressed = self.decompress_mam(self.data)
                if decompressed:
                    self.data = decompressed
                    if self.verbose:
                        print(f"  Decompression: Success ({len(self.data)} bytes)")
                else:
                    self.forensic_data['parsing_errors'].append("MAM decompression failed")
                    if self.verbose:
                        print(f"  Decompression: Failed")
                    # Still try to get basic info from the file
                    self.parse_execution_info()
                    return self.forensic_data
            elif self.verbose:
                print(f"\n  File: {self.file_name}")
                print(f"  Compressed: No")
            
            # Parse header - check for valid signatures
            signature = self.data[:4]
            if signature == b'SCCA':
                self.forensic_data['signature'] = 'SCCA'
            elif signature[:3] == b'ECS':
                self.forensic_data['signature'] = 'ECS'
            else:
                # Some prefetch files start with version directly
                pass
            
            # Version is at offset 0 (first 4 bytes) but only use first byte
            version_full = struct.unpack('<I', self.data[0:4])[0]
            self.forensic_data['version'] = version_full & 0xFF
            
            if self.verbose:
                print(f"  Version detected: 0x{self.forensic_data['version']:02X}")
                print(f"  First 8 bytes: {self.data[:8].hex()}")
            
            # Common versions: 0x17 (Win8), 0x1A (Win8.1), 0x1E (Win10), 0x1F-0x24 (Win10/11)
            if self.forensic_data['version'] not in [0x11, 0x17, 0x1A, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24]:
                # Try alternative: version might be at offset 4
                if len(self.data) > 4:
                    alt_version = struct.unpack('<I', self.data[4:8])[0] & 0xFF
                    if alt_version in [0x11, 0x17, 0x1A, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24]:
                        self.forensic_data['version'] = alt_version
            
            # Always try to parse execution info regardless of other parsing
            self.parse_execution_info()
            
            # Parse file information based on version if we have a valid version
            if self.forensic_data['version'] >= 0x17:  # Win8+
                try:
                    # File metrics array offset
                    if len(self.data) > 0x84:
                        metrics_offset = struct.unpack('<I', self.data[0x80:0x84])[0]
                        metrics_count = struct.unpack('<I', self.data[0x84:0x88])[0]
                        
                        # Validate offsets
                        if 0 < metrics_offset < len(self.data) and 0 < metrics_count < 100000:
                            # Trace chains array offset  
                            if len(self.data) > 0x90:
                                trace_offset = struct.unpack('<I', self.data[0x88:0x8C])[0]
                                trace_count = struct.unpack('<I', self.data[0x8C:0x90])[0]
                                
                                # Filename strings offset
                                if len(self.data) > 0x98:
                                    strings_offset = struct.unpack('<I', self.data[0x90:0x94])[0]
                                    strings_size = struct.unpack('<I', self.data[0x94:0x98])[0]
                                    
                                    # Volume information offset
                                    if len(self.data) > 0xA0:
                                        volumes_offset = struct.unpack('<I', self.data[0x98:0x9C])[0]
                                        volumes_count = struct.unpack('<I', self.data[0x9C:0xA0])[0]
                                        
                                        # Parse volumes
                                        if volumes_offset > 0 and volumes_count > 0 and volumes_offset < len(self.data):
                                            self.forensic_data['volumes'] = self.parse_volume_information(volumes_offset, volumes_count)
                                        
                                        # Parse file references
                                        if metrics_offset > 0 and metrics_count > 0 and strings_offset > 0:
                                            self.forensic_data['files_accessed'] = self.parse_file_information_array(
                                                metrics_offset, min(metrics_count, 1000), strings_offset)
                                        
                                        # Parse trace chains
                                        if trace_offset > 0 and trace_count > 0 and trace_offset < len(self.data):
                                            self.forensic_data['trace_chains'] = self.parse_trace_chains(trace_offset, trace_count)
                                        
                                        # Extract directories from filename strings
                                        if strings_offset > 0 and strings_size > 0 and strings_offset < len(self.data):
                                            self.extract_directory_strings(strings_offset, min(strings_size, len(self.data) - strings_offset))
                except Exception as e:
                    self.forensic_data['parsing_errors'].append(f"File structure parsing error: {str(e)}")
            
            # Extract DLL information from filenames
            self.extract_dll_info()
            
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"General parsing error: {str(e)}")
        
        return self.forensic_data
    
    def parse_execution_info(self):
        """Parse execution count and timestamps"""
        try:
            # Try to get execution count - location varies by version
            exec_count = 0
            if self.forensic_data['version']:
                if self.forensic_data['version'] == 0x17 and len(self.data) > 0x9C:
                    exec_count = struct.unpack('<I', self.data[0x98:0x9C])[0]
                elif self.forensic_data['version'] in [0x1A, 0x1E] and len(self.data) > 0xD4:
                    exec_count = struct.unpack('<I', self.data[0xD0:0xD4])[0]
                elif len(self.data) > 0xD4:
                    exec_count = struct.unpack('<I', self.data[0xD0:0xD4])[0]
                
            self.forensic_data['execution_count'] = exec_count if exec_count < 10000 else 0
            
            # Parse timestamps - try multiple offsets regardless of version
            offset_mappings = {
                0x17: [0x80],
                0x1A: [0x78, 0x80],
                0x1E: [0x80, 0x98],
                0x1F: [0x80, 0x98, 0xD0],
                0x20: [0x80, 0x98, 0xB0],
                0x21: [0x80, 0xD0, 0x98],
                0x22: [0x80, 0xD0, 0x98],
                0x23: [0x80, 0xD0, 0x98],
                0x24: [0x80, 0xD0, 0x98]
            }
            
            # Get offsets to try based on version, or use all common ones
            if self.forensic_data['version'] in offset_mappings:
                offsets_to_try = offset_mappings[self.forensic_data['version']]
            else:
                offsets_to_try = []
                
            # Always add common offsets as fallback
            offsets_to_try.extend([0x80, 0xD0, 0x98, 0x78, 0x90, 0xB0, 0xC8])
            offsets_to_try = list(dict.fromkeys(offsets_to_try))  # Remove duplicates
            
            for offset in offsets_to_try:
                if offset + 64 > len(self.data):
                    continue
                    
                valid_timestamps_found = False
                for i in range(8):
                    ft_offset = offset + (i * 8)
                    if ft_offset + 8 > len(self.data):
                        break
                        
                    try:
                        ft = struct.unpack('<Q', self.data[ft_offset:ft_offset+8])[0]
                        
                        # Skip invalid values
                        if ft == 0 or ft == 0xFFFFFFFFFFFFFFFF:
                            continue
                            
                        # Validate range (1990-2030)
                        if ft < 116444736000000000 or ft > 159725856000000000:
                            continue
                            
                        run_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft/10)
                        if run_time.year >= 1990 and run_time.year <= 2030:
                            self.forensic_data['execution_times'].append({
                                'timestamp': run_time.isoformat(),
                                'slot': i + 1,
                                'offset': f"0x{offset:X}"
                            })
                            valid_timestamps_found = True
                    except:
                        continue
                        
                # If we found valid timestamps at this offset, we can stop
                if valid_timestamps_found:
                    if self.verbose:
                        print(f"  Found {len([t for t in self.forensic_data['execution_times'] if t['offset'] == f'0x{offset:X}'])} timestamps at offset 0x{offset:X}")
                    break
                    
            # If no timestamps found but not MAM compressed, use file modified time
            if not self.forensic_data['execution_times'] and not self.forensic_data['mam_compressed']:
                try:
                    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(self.file_path))
                    self.forensic_data['execution_times'].append({
                        'timestamp': mod_time.isoformat(),
                        'slot': 0,
                        'offset': 'FileModTime'
                    })
                    if self.verbose:
                        print(f"  Using file modification time: {mod_time}")
                except:
                    pass
            elif not self.forensic_data['execution_times'] and self.forensic_data['mam_compressed']:
                # For MAM files that failed to decompress, use file time
                try:
                    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(self.file_path))
                    self.forensic_data['execution_times'].append({
                        'timestamp': mod_time.isoformat(),
                        'slot': 0,
                        'offset': 'FileModTime (MAM failed)'
                    })
                    if self.verbose:
                        print(f"  Using file modification time (MAM failed): {mod_time}")
                except:
                    pass
                    
            # Set last execution time
            if self.forensic_data['execution_times']:
                self.forensic_data['last_execution'] = max(
                    self.forensic_data['execution_times'], 
                    key=lambda x: x['timestamp']
                )['timestamp']
                
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"Execution info parsing error: {str(e)}")
    
    def extract_directory_strings(self, offset, size):
        """Extract directory paths from filename strings section"""
        try:
            strings_data = self.data[offset:offset + size]
            
            # Extract Unicode strings
            current_string = b''
            for i in range(0, len(strings_data)-1, 2):
                two_bytes = strings_data[i:i+2]
                if two_bytes == b'\x00\x00':
                    if current_string:
                        try:
                            string = current_string.decode('utf-16-le', errors='ignore')
                            if '\\' in string and len(string) > 3:
                                # Extract directory path
                                if string.startswith('\\'):
                                    dir_path = os.path.dirname(string)
                                    if dir_path and dir_path not in self.forensic_data['directories']:
                                        self.forensic_data['directories'].append(dir_path)
                        except:
                            pass
                        current_string = b''
                else:
                    current_string += two_bytes
                    
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"Directory extraction error: {str(e)}")
    
    def extract_dll_info(self):
        """Extract loaded DLLs from file references"""
        try:
            for file_ref in self.forensic_data['files_accessed']:
                if file_ref['filename'].lower().endswith('.dll'):
                    dll_name = os.path.basename(file_ref['filename'])
                    if dll_name not in self.forensic_data['loaded_dlls']:
                        self.forensic_data['loaded_dlls'].append(dll_name)
                        
        except Exception as e:
            self.forensic_data['parsing_errors'].append(f"DLL extraction error: {str(e)}")

def print_forensic_report(forensic_data, detailed=False, log_file=None):
    """Print a formatted forensic report"""
    output = []
    
    output.append(f"\n{Color.CYAN}{'='*80}{Color.RESET}")
    output.append(f"{Color.CYAN}=== Forensic Analysis: {forensic_data['file_name']} ==={Color.RESET}")
    output.append(f"{Color.CYAN}{'='*80}{Color.RESET}")
    output.append(f"Process: {Color.YELLOW}{forensic_data['process_name']}{Color.RESET}")
    output.append(f"Hash: {forensic_data['hash']}")
    output.append(f"Size: {forensic_data['file_size']:,} bytes")
    output.append(f"Created: {forensic_data['created']}")
    output.append(f"Modified: {forensic_data['modified']}")
    output.append(f"Version: 0x{forensic_data['version']:02X}" if forensic_data['version'] else "Unknown")
    output.append(f"Compressed: {'Yes (MAM)' if forensic_data['mam_compressed'] else 'No'}")
    
    # Execution information
    output.append(f"\n{Color.GREEN}Execution Information:{Color.RESET}")
    output.append(f"Execution Count: {forensic_data['execution_count']}")
    output.append(f"Total Timestamps Found: {len(forensic_data['execution_times'])}")
    if forensic_data['last_execution']:
        # Format the timestamp nicely
        try:
            last_exec_dt = datetime.datetime.fromisoformat(forensic_data['last_execution'].replace('T', ' '))
            output.append(f"Last Execution: {last_exec_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except:
            output.append(f"Last Execution: {forensic_data['last_execution']}")
    
    if forensic_data['execution_times']:
        output.append("\nExecution Timeline:")
        for exec_time in sorted(forensic_data['execution_times'], key=lambda x: x['timestamp'], reverse=True):
            try:
                exec_dt = datetime.datetime.fromisoformat(exec_time['timestamp'].replace('T', ' '))
                time_str = exec_dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                time_str = exec_time['timestamp']
            output.append(f"  {time_str} (Slot {exec_time['slot']}, Offset {exec_time['offset']})")
    
    # Volume information
    if forensic_data['volumes']:
        output.append(f"\n{Color.BLUE}Volume Information:{Color.RESET}")
        for vol in forensic_data['volumes']:
            output.append(f"  Path: {vol['path']}")
            output.append(f"  Serial: {vol['serial_number']}")
            if vol['creation_time']:
                output.append(f"  Created: {vol['creation_time']}")
            output.append("")
    
    # File access statistics
    if forensic_data['files_accessed']:
        output.append(f"\n{Color.MAGENTA}File Access Statistics:{Color.RESET}")
        output.append(f"Total Files Accessed: {len(forensic_data['files_accessed'])}")
        
        # Top accessed files
        top_files = sorted(forensic_data['files_accessed'], 
                          key=lambda x: x['prefetch_count'], reverse=True)[:10]
        output.append("\nTop 10 Most Accessed Files:")
        for f in top_files:
            output.append(f"  {f['prefetch_count']:3d}x - {f['filename']}")
    
    # Loaded DLLs
    if forensic_data['loaded_dlls']:
        output.append(f"\n{Color.YELLOW}Loaded DLLs ({len(forensic_data['loaded_dlls'])}):{Color.RESET}")
        for dll in sorted(forensic_data['loaded_dlls'])[:20]:
            output.append(f"  {dll}")
        if len(forensic_data['loaded_dlls']) > 20:
            output.append(f"  ... and {len(forensic_data['loaded_dlls']) - 20} more")
    
    # Directories accessed
    if forensic_data['directories']:
        output.append(f"\n{Color.CYAN}Directories Accessed ({len(forensic_data['directories'])}):{Color.RESET}")
        for dir_path in sorted(forensic_data['directories'])[:15]:
            output.append(f"  {dir_path}")
        if len(forensic_data['directories']) > 15:
            output.append(f"  ... and {len(forensic_data['directories']) - 15} more")
    
    # Trace chains (memory access patterns)
    if forensic_data['trace_chains']:
        output.append(f"\n{Color.RED}Memory Access Patterns:{Color.RESET}")
        output.append(f"Total Trace Chains: {len(forensic_data['trace_chains'])}")
        total_blocks = sum(tc['block_count'] for tc in forensic_data['trace_chains'])
        output.append(f"Total Memory Blocks: {total_blocks:,}")
    
    # Parsing errors
    if forensic_data['parsing_errors']:
        output.append(f"\n{Color.RED}Parsing Issues:{Color.RESET}")
        for error in forensic_data['parsing_errors']:
            output.append(f"  - {error}")
    
    if detailed and forensic_data['files_accessed']:
        output.append(f"\n{Color.WHITE}=== Detailed File List ==={Color.RESET}")
        for f in sorted(forensic_data['files_accessed'], key=lambda x: x['filename']):
            output.append(f"{f['prefetch_count']:3d}x - {f['filename']}")
    
    # Print to console
    for line in output:
        print(line)
    
    # Write to log file if specified
    if log_file:
        # Strip color codes for file output
        clean_output = []
        for line in output:
            clean_line = line
            for color in [Color.RED, Color.GREEN, Color.YELLOW, Color.BLUE, 
                         Color.MAGENTA, Color.CYAN, Color.WHITE, Color.RESET]:
                clean_line = clean_line.replace(color, '')
            clean_output.append(clean_line)
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(clean_output) + '\n')

def generate_execution_timeline(all_results, log_file=None, start_date=None, end_date=None, off_hours_only=False):
    """Generate a time-sorted execution timeline with off-hours highlighting"""
    # Define off-hours (11 PM to 6 AM)
    off_hours_start = 23  # 11 PM
    off_hours_end = 6     # 6 AM
    
    # Collect all executions from all files
    all_executions = []
    
    for result in all_results:
        for exec_time in result['execution_times']:
            try:
                # Parse timestamp
                timestamp_str = exec_time['timestamp']
                if 'T' in timestamp_str:
                    exec_dt = datetime.datetime.fromisoformat(timestamp_str.replace('T', ' '))
                else:
                    exec_dt = datetime.datetime.fromisoformat(timestamp_str)
                
                # Apply date filters if specified
                if start_date and exec_dt.date() < start_date:
                    continue
                if end_date and exec_dt.date() > end_date:
                    continue
                
                # Apply off-hours filter if specified
                if off_hours_only:
                    hour = exec_dt.hour
                    if not (hour >= off_hours_start or hour <= off_hours_end):
                        continue
                
                all_executions.append({
                    'timestamp': exec_dt,
                    'process': result['process_name'],
                    'file': result['file_name'],
                    'slot': exec_time['slot'],
                    'offset': exec_time['offset']
                })
            except:
                pass
    
    # Sort by timestamp
    all_executions.sort(key=lambda x: x['timestamp'])
    
    if not all_executions:
        return
    
    output = []
    output.append(f"\n{Color.CYAN}{'='*100}{Color.RESET}")
    output.append(f"{Color.CYAN}=== CHRONOLOGICAL EXECUTION TIMELINE ==={Color.RESET}")
    output.append(f"{Color.CYAN}{'='*100}{Color.RESET}")
    
    # Show filters if applied
    filters = []
    if start_date or end_date:
        if start_date and end_date:
            filters.append(f"Date: {start_date} to {end_date}")
        elif start_date:
            filters.append(f"From: {start_date}")
        else:
            filters.append(f"Until: {end_date}")
    
    if off_hours_only:
        filters.append("Off-hours only (11PM-6AM)")
        
    if filters:
        output.append(f"{Color.YELLOW}Filters applied: {', '.join(filters)}{Color.RESET}")
    
    output.append(f"Total executions: {len(all_executions)}")
    
    # Time range
    earliest = all_executions[0]['timestamp']
    latest = all_executions[-1]['timestamp']
    output.append(f"Time range: {earliest.strftime('%Y-%m-%d %H:%M:%S')} to {latest.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append(f"Duration: {(latest - earliest).days} days, {(latest - earliest).seconds // 3600} hours\n")
    
    output.append(f"{Color.MAGENTA}Note: Off-hours are defined as 11:00 PM to 6:00 AM{Color.RESET}\n")
    
    # Statistics
    off_hours_count = 0
    weekend_count = 0
    suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                           'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'certutil.exe',
                           'bitsadmin.exe', 'msiexec.exe', 'installutil.exe']
    suspicious_count = 0
    
    # Count statistics
    for exe in all_executions:
        hour = exe['timestamp'].hour
        if hour >= off_hours_start or hour <= off_hours_end:
            off_hours_count += 1
        if exe['timestamp'].weekday() >= 5:  # Saturday = 5, Sunday = 6
            weekend_count += 1
        if any(s in exe['process'].lower() for s in suspicious_processes):
            suspicious_count += 1
    
    output.append(f"{Color.YELLOW}Activity Statistics:{Color.RESET}")
    output.append(f"  Off-hours executions (11PM-6AM): {Color.RED}{off_hours_count}{Color.RESET} ({off_hours_count/len(all_executions)*100:.1f}%)")
    output.append(f"  Weekend executions: {Color.YELLOW}{weekend_count}{Color.RESET} ({weekend_count/len(all_executions)*100:.1f}%)")
    output.append(f"  Suspicious process executions: {Color.RED}{suspicious_count}{Color.RESET} ({suspicious_count/len(all_executions)*100:.1f}%)\n")
    
    # Group by date
    date_groups = defaultdict(list)
    for exe in all_executions:
        date_key = exe['timestamp'].date()
        date_groups[date_key].append(exe)
    
    output.append(f"{Color.GREEN}Execution Timeline by Date:{Color.RESET}")
    output.append("-" * 100)
    output.append(f"{'Date':<12} {'Time':<10} {'Day':<4} {'Process':<30} {'Prefetch File':<35} {'Notes':<20}")
    output.append("-" * 100)
    
    # Display timeline
    for date in sorted(date_groups.keys()):
        # Add date header
        day_name = date.strftime('%a')
        is_weekend = date.weekday() >= 5
        
        date_header = f"\n{Color.BLUE}{date.strftime('%Y-%m-%d')} ({day_name})"
        if is_weekend:
            date_header += f" [WEEKEND]"
        date_header += f"{Color.RESET}"
        output.append(date_header)
        
        # Show executions for this date
        for exe in sorted(date_groups[date], key=lambda x: x['timestamp']):
            time_str = exe['timestamp'].strftime('%H:%M:%S')
            hour = exe['timestamp'].hour
            day_abbr = exe['timestamp'].strftime('%a')
            
            # Determine if off-hours
            is_off_hours = hour >= off_hours_start or hour <= off_hours_end
            is_suspicious = any(s in exe['process'].lower() for s in suspicious_processes)
            
            # Build the line with appropriate coloring
            line_parts = []
            
            # Date (already shown in header)
            line_parts.append(f"{'':12}")
            
            # Time with off-hours highlighting
            if is_off_hours:
                line_parts.append(f"{Color.RED}{time_str:<10}{Color.RESET}")
            else:
                line_parts.append(f"{time_str:<10}")
            
            # Day
            line_parts.append(f"{day_abbr:<4}")
            
            # Process name with suspicious highlighting
            if is_suspicious:
                line_parts.append(f"{Color.YELLOW}{exe['process']:<30}{Color.RESET}")
            else:
                line_parts.append(f"{exe['process']:<30}")
            
            # Prefetch file
            line_parts.append(f"{exe['file']:<35}")
            
            # Notes
            notes = []
            if is_off_hours:
                notes.append("[!] OFF-HOURS")
            if is_weekend:
                notes.append("[W] WEEKEND")
            if is_suspicious:
                notes.append("[S] SUSPICIOUS")
            if exe['slot'] == 0:
                notes.append("[F] FALLBACK")
                
            note_str = ', '.join(notes)
            if notes:
                line_parts.append(f"{Color.MAGENTA}{note_str:<20}{Color.RESET}")
            else:
                line_parts.append(f"{'':<20}")
            
            output.append(''.join(line_parts))
    
    # Hourly distribution
    output.append(f"\n{Color.YELLOW}Hourly Activity Distribution:{Color.RESET}")
    output.append("-" * 60)
    
    hourly_counts = Counter(exe['timestamp'].hour for exe in all_executions)
    max_count = max(hourly_counts.values()) if hourly_counts else 1
    
    for hour in range(24):
        count = hourly_counts.get(hour, 0)
        bar_length = int(count * 40 / max_count) if max_count > 0 else 0
        bar = '█' * bar_length
        
        # Color based on off-hours
        if hour >= off_hours_start or hour <= off_hours_end:
            output.append(f"{Color.RED}{hour:02d}:00-{hour:02d}:59 {count:>4} {bar}{Color.RESET}")
        else:
            output.append(f"{hour:02d}:00-{hour:02d}:59 {count:>4} {Color.BLUE}{bar}{Color.RESET}")
    
    # Most active hours
    output.append(f"\n{Color.YELLOW}Most Active Hours:{Color.RESET}")
    for hour, count in hourly_counts.most_common(5):
        time_range = f"{hour:02d}:00-{hour:02d}:59"
        if hour >= off_hours_start or hour <= off_hours_end:
            output.append(f"  {Color.RED}{time_range}: {count} executions (OFF-HOURS){Color.RESET}")
        else:
            output.append(f"  {time_range}: {count} executions")
    
    # Suspicious off-hours activity
    suspicious_off_hours = []
    for exe in all_executions:
        hour = exe['timestamp'].hour
        if (hour >= off_hours_start or hour <= off_hours_end) and \
           any(s in exe['process'].lower() for s in suspicious_processes):
            suspicious_off_hours.append(exe)
    
    if suspicious_off_hours:
        output.append(f"\n{Color.RED}[!] SUSPICIOUS OFF-HOURS ACTIVITY DETECTED [!]{Color.RESET}")
        output.append(f"Found {len(suspicious_off_hours)} suspicious process executions during off-hours:\n")
        
        for exe in sorted(suspicious_off_hours, key=lambda x: x['timestamp'])[:20]:  # Show first 20
            output.append(f"  {Color.RED}{exe['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - "
                         f"{exe['process']} ({exe['timestamp'].strftime('%A')}){Color.RESET}")
        
        if len(suspicious_off_hours) > 20:
            output.append(f"  ... and {len(suspicious_off_hours) - 20} more")
    
    # Daily summary statistics
    output.append(f"\n{Color.CYAN}Daily Activity Summary:{Color.RESET}")
    output.append("-" * 80)
    output.append(f"{'Date':<12} {'Total':<8} {'Off-hrs':<8} {'Suspicious':<12} {'Top Process':<30}")
    output.append("-" * 80)
    
    for date in sorted(date_groups.keys()):
        day_execs = date_groups[date]
        day_name = date.strftime('%a')
        is_weekend = date.weekday() >= 5
        
        # Count off-hours
        off_hrs_count = sum(1 for e in day_execs if e['timestamp'].hour >= off_hours_start or e['timestamp'].hour <= off_hours_end)
        
        # Count suspicious
        susp_count = sum(1 for e in day_execs if any(s in e['process'].lower() for s in suspicious_processes))
        
        # Top process
        process_counts = Counter(e['process'] for e in day_execs)
        top_process = process_counts.most_common(1)[0] if process_counts else ('', 0)
        
        # Format line with proper spacing accounting for color codes
        if is_weekend:
            line = f"{Color.YELLOW}{date.strftime('%Y-%m-%d')}{Color.RESET} "
        else:
            line = f"{date.strftime('%Y-%m-%d')} "
        
        line += f"{len(day_execs):<8} "
        
        if off_hrs_count > 10:
            line += f"{Color.RED}{off_hrs_count:<8}{Color.RESET} "
        elif off_hrs_count > 0:
            line += f"{Color.YELLOW}{off_hrs_count:<8}{Color.RESET} "
        else:
            line += f"{off_hrs_count:<8} "
            
        if susp_count > 0:
            line += f"{Color.RED}{susp_count:<12}{Color.RESET} "
        else:
            line += f"{susp_count:<12} "
            
        line += f"{top_process[0]} ({top_process[1]}x)"
        
        output.append(line)
    
    # Most frequently executed processes during off-hours
    off_hours_processes = Counter()
    for exe in all_executions:
        hour = exe['timestamp'].hour
        if hour >= off_hours_start or hour <= off_hours_end:
            off_hours_processes[exe['process']] += 1
    
    if off_hours_processes:
        output.append(f"\n{Color.YELLOW}Top Processes Executed During Off-Hours (11PM-6AM):{Color.RESET}")
        for process, count in off_hours_processes.most_common(10):
            is_suspicious = any(s in process.lower() for s in suspicious_processes)
            if is_suspicious:
                output.append(f"  {Color.RED}{process}: {count} executions [!]{Color.RESET}")
            else:
                output.append(f"  {process}: {count} executions")
    
    # Detect rapid execution bursts (5+ executions within 2 minutes)
    output.append(f"\n{Color.YELLOW}Rapid Execution Bursts Detection:{Color.RESET}")
    
    bursts = []
    window_minutes = 2
    min_burst_size = 5
    
    for i in range(len(all_executions)):
        burst_start = all_executions[i]['timestamp']
        burst_end = burst_start + datetime.timedelta(minutes=window_minutes)
        burst_execs = [all_executions[i]]
        
        # Collect executions within window
        for j in range(i + 1, len(all_executions)):
            if all_executions[j]['timestamp'] <= burst_end:
                burst_execs.append(all_executions[j])
            else:
                break
        
        if len(burst_execs) >= min_burst_size:
            # Check if this burst overlaps with existing ones
            is_new_burst = True
            for existing_burst in bursts:
                if burst_start <= existing_burst['end'] and burst_execs[-1]['timestamp'] >= existing_burst['start']:
                    is_new_burst = False
                    break
            
            if is_new_burst:
                bursts.append({
                    'start': burst_start,
                    'end': burst_execs[-1]['timestamp'],
                    'executions': burst_execs,
                    'count': len(burst_execs),
                    'duration': (burst_execs[-1]['timestamp'] - burst_start).total_seconds()
                })
    
    if bursts:
        output.append(f"\n{Color.RED}[!] RAPID EXECUTION BURSTS DETECTED [!]{Color.RESET}")
        output.append(f"Found {len(bursts)} burst(s) of rapid execution:\n")
        
        for i, burst in enumerate(sorted(bursts, key=lambda x: x['count'], reverse=True)[:10]):
            output.append(f"{Color.YELLOW}Burst #{i+1}: {burst['count']} executions in {burst['duration']:.1f} seconds{Color.RESET}")
            output.append(f"  Time: {burst['start'].strftime('%Y-%m-%d %H:%M:%S')} to {burst['end'].strftime('%H:%M:%S')}")
            
            # Show unique processes in burst
            burst_processes = Counter(e['process'] for e in burst['executions'])
            output.append(f"  Processes: {', '.join(f'{p} ({c}x)' for p, c in burst_processes.most_common())}")
            
            # Check if burst occurred during off-hours
            if burst['start'].hour >= off_hours_start or burst['start'].hour <= off_hours_end:
                output.append(f"  {Color.RED}[!] OCCURRED DURING OFF-HOURS!{Color.RESET}")
            
            output.append("")
    else:
        output.append("No rapid execution bursts detected.\n")
    
    # Print to console
    for line in output:
        print(line)
    
    # Write to log file
    if log_file:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write('\n')
            for line in output:
                # Strip color codes
                clean_line = line
                for color in [Color.RED, Color.GREEN, Color.YELLOW, Color.BLUE, 
                             Color.MAGENTA, Color.CYAN, Color.WHITE, Color.RESET]:
                    clean_line = clean_line.replace(color, '')
                f.write(clean_line + '\n')

def main():
    Color.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(description='Advanced Prefetch Forensic Analyzer')
    parser.add_argument('prefetch_file', nargs='?', help='Specific prefetch file to analyze')
    parser.add_argument('--all', action='store_true', help='Analyze all prefetch files')
    parser.add_argument('--path', default=r'C:\Windows\Prefetch', help='Prefetch directory path')
    parser.add_argument('--output', help='Output JSON file for results')
    parser.add_argument('--detailed', action='store_true', help='Show detailed file lists')
    parser.add_argument('--process', help='Filter by process name')
    parser.add_argument('--suspicious', action='store_true', help='Analyze only suspicious processes')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output for debugging')
    parser.add_argument('--summary-only', action='store_true', help='Show only summary statistics')
    parser.add_argument('--log', help='Log all output to file (in addition to console)')
    parser.add_argument('--no-timeline', action='store_true', help='Skip the execution timeline')
    parser.add_argument('--start-date', help='Start date for timeline filter (YYYY-MM-DD)')
    parser.add_argument('--end-date', help='End date for timeline filter (YYYY-MM-DD)')
    parser.add_argument('--off-hours-only', action='store_true', help='Show only off-hours executions in timeline')
    
    args = parser.parse_args()
    
    if not args.prefetch_file and not args.all:
        parser.error("Specify a prefetch file or use --all to analyze all files")
    
    print(f"{Color.CYAN}=== Advanced Prefetch Forensic Analyzer ==={Color.RESET}")
    print(f"Extracts execution times, file access, volumes, DLLs, and more\n")
    
    # Set up log file if specified
    log_file = args.log
    if not log_file and args.all and not args.summary_only:
        # Auto-generate log file name for --all analysis
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = f"prefetch_forensics_{timestamp}.txt"
        print(f"Auto-saving output to: {Color.GREEN}{log_file}{Color.RESET}")
    
    if log_file:
        # Create/clear the log file
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"Advanced Prefetch Forensic Analysis Report\n")
            f.write(f"Generated: {datetime.datetime.now()}\n")
            f.write(f"{'='*80}\n\n")
        if args.log:  # Only show this if explicitly specified
            print(f"Logging output to: {Color.GREEN}{log_file}{Color.RESET}")
    
    files_to_analyze = []
    
    if args.all:
        if not os.path.exists(args.path):
            print(f"{Color.RED}Error: Prefetch directory not found: {args.path}{Color.RESET}")
            sys.exit(1)
            
        pf_files = list(Path(args.path).glob("*.pf"))
        
        if args.process:
            pf_files = [f for f in pf_files if args.process.lower() in f.name.lower()]
            
        if args.suspicious:
            suspicious = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 
                         'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'certutil.exe',
                         'bitsadmin.exe', 'msiexec.exe', 'wusa.exe', 'installutil.exe',
                         'taskhost.exe', 'conhost.exe', 'schtasks.exe']
            pf_files = [f for f in pf_files 
                       if any(s in f.name.lower() for s in suspicious)]
        
        files_to_analyze = [str(f) for f in pf_files]
        print(f"Found {len(files_to_analyze)} prefetch files to analyze")
        
        if len(files_to_analyze) > 50 and not args.summary_only and not args.output:
            print(f"\n{Color.YELLOW}Note: Analyzing {len(files_to_analyze)} files with full output.{Color.RESET}")
            print("Consider using:")
            print("  --summary-only  : For summary statistics only")
            print("  --no-timeline   : Skip the chronological timeline")
            print("  --suspicious    : To analyze only suspicious processes")
            print("  --process NAME  : To filter by specific process")
            print(f"\n{Color.CYAN}Full analysis will be saved to: {log_file if log_file else 'auto-generated file'}{Color.RESET}")
            print(f"{Color.GREEN}The timeline will highlight off-hours (11PM-6AM) and suspicious activity{Color.RESET}\n")
    else:
        if not os.path.exists(args.prefetch_file):
            print(f"{Color.RED}Error: File not found: {args.prefetch_file}{Color.RESET}")
            sys.exit(1)
        files_to_analyze = [args.prefetch_file]
    
    all_results = []
    failed_files = []
    
    if not args.summary_only:
        print("\nAnalyzing prefetch files...\n")
    else:
        print("\nParsing prefetch files...")
        
    for i, pf_file in enumerate(files_to_analyze):
        if args.summary_only and len(files_to_analyze) > 1:
            print(f"\rProcessing: {i+1}/{len(files_to_analyze)} files...", end='', flush=True)
        elif not args.summary_only and len(files_to_analyze) > 1:
            # Show progress for full analysis too
            print(f"\n{Color.BLUE}[{i+1}/{len(files_to_analyze)}] Analyzing: {os.path.basename(pf_file)}{Color.RESET}")
        
        analyzer = PrefetchForensics(pf_file, verbose=args.verbose)
        forensic_data = analyzer.parse()
        
        # Show detailed report unless summary-only is specified
        if not args.summary_only:
            print_forensic_report(forensic_data, detailed=args.detailed, log_file=log_file)
        elif len(files_to_analyze) == 1:
            # Always show report for single file analysis
            print_forensic_report(forensic_data, detailed=args.detailed, log_file=log_file)
        
        all_results.append(forensic_data)
        
        # Track failed files
        if forensic_data['parsing_errors']:
            failed_files.append(os.path.basename(pf_file))
    
    if args.summary_only and len(files_to_analyze) > 1:
        print(f"\rProcessed all {len(files_to_analyze)} files successfully!                    ")
    
    # Summary statistics for multiple files
    if len(files_to_analyze) > 1:
        summary = []
        summary.append(f"\n{Color.YELLOW}{'='*80}{Color.RESET}")
        summary.append(f"{Color.YELLOW}=== FINAL SUMMARY STATISTICS ==={Color.RESET}")
        summary.append(f"{Color.YELLOW}{'='*80}{Color.RESET}")
        summary.append(f"Total files analyzed: {len(all_results)}")
        
        # Count MAM compressed files
        mam_count = sum(1 for r in all_results if r['mam_compressed'])
        summary.append(f"MAM compressed files: {Color.CYAN}{mam_count}{Color.RESET}")
        
        # Files with successful timestamp extraction
        files_with_times = sum(1 for r in all_results if r['execution_times'])
        summary.append(f"Files with execution times: {Color.GREEN}{files_with_times}{Color.RESET}")
        
        total_executions = sum(len(r['execution_times']) for r in all_results)
        summary.append(f"Total executions found: {Color.GREEN}{total_executions}{Color.RESET}")
        
        total_files_accessed = sum(len(r['files_accessed']) for r in all_results)
        summary.append(f"Total files accessed: {total_files_accessed}")
        
        all_dlls = set()
        for r in all_results:
            all_dlls.update(r['loaded_dlls'])
        summary.append(f"Total unique DLLs loaded: {len(all_dlls)}")
        
        parsing_errors = sum(1 for r in all_results if r['parsing_errors'])
        summary.append(f"Files with parsing errors: {Color.RED}{parsing_errors}{Color.RESET}")
        
        # Show example errors if verbose
        if args.verbose and failed_files:
            summary.append(f"\n{Color.RED}Failed files examples:{Color.RESET}")
            for f in failed_files[:5]:
                summary.append(f"  - {f}")
            if len(failed_files) > 5:
                summary.append(f"  ... and {len(failed_files) - 5} more")
                
        # Show some successfully parsed files
        successful_examples = [r for r in all_results if r['execution_times'] and not r['parsing_errors']]
        if successful_examples:
            summary.append(f"\n{Color.GREEN}Successfully parsed examples:{Color.RESET}")
            for r in successful_examples[:5]:
                summary.append(f"  - {r['file_name']}: {len(r['execution_times'])} executions, "
                      f"last: {r['last_execution'][:19] if r['last_execution'] else 'N/A'}")
                      
        # Show advice if all files failed
        if parsing_errors == len(all_results):
            summary.append(f"\n{Color.RED}All files failed to parse!{Color.RESET}")
            summary.append("This might be due to:")
            summary.append("  1. MAM compression (Windows 11) - decompression may have failed")
            summary.append("  2. Different prefetch format version")
            summary.append("  3. Corrupted prefetch files")
            summary.append("  4. Permission issues")
            summary.append("\nTry running with --verbose flag for more details")
        
        # Print summary to console
        for line in summary:
            print(line)
        
        # Write summary to log file
        if log_file:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write("\n")
                for line in summary:
                    # Strip color codes
                    clean_line = line
                    for color in [Color.RED, Color.GREEN, Color.YELLOW, Color.BLUE, 
                                 Color.MAGENTA, Color.CYAN, Color.WHITE, Color.RESET]:
                        clean_line = clean_line.replace(color, '')
                    f.write(clean_line + '\n')
    
    # Generate execution timeline
    if all_results and not args.no_timeline:
        # Show timeline for multiple files or single file with multiple executions
        total_execs = sum(len(r['execution_times']) for r in all_results)
        if (len(files_to_analyze) > 1 or total_execs > 1) and not args.summary_only:
            # Parse date filters
            start_date = None
            end_date = None
            
            if args.start_date:
                try:
                    start_date = datetime.datetime.strptime(args.start_date, '%Y-%m-%d').date()
                except ValueError:
                    print(f"{Color.RED}Invalid start date format. Use YYYY-MM-DD{Color.RESET}")
                    
            if args.end_date:
                try:
                    end_date = datetime.datetime.strptime(args.end_date, '%Y-%m-%d').date()
                except ValueError:
                    print(f"{Color.RED}Invalid end date format. Use YYYY-MM-DD{Color.RESET}")
                    
            generate_execution_timeline(all_results, log_file, start_date, end_date, args.off_hours_only)
    
    # Export results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n{Color.GREEN}JSON results exported to: {args.output}{Color.RESET}")
    
    # Final message
    if log_file:
        print(f"\n{Color.GREEN}Complete analysis saved to: {log_file}{Color.RESET}")
        print(f"File contains all forensic data for {len(all_results)} prefetch files")

if __name__ == "__main__":
    main()
