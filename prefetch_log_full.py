#!/usr/bin/env python3
"""
Prefetch Analyzer
Optimized for wide terminal displays and maximum information density
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
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
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

def print_forensic_report_compact(forensic_data, log_file=None):
    """Print a compact forensic report optimized for wide displays"""
    output = []
    
    # Extract process name without extension
    process_name = forensic_data['process_name']
    if process_name.upper().endswith('.EXE'):
        process_name = process_name[:-4]
    
    # Header with key info in one line
    header = f"{Color.CYAN}▶ {process_name:<20}{Color.RESET} "
    header += f"Hash:{forensic_data['hash'][:8] if forensic_data['hash'] else 'N/A'} "
    header += f"V:{forensic_data['version']:02X} " if forensic_data['version'] else "V:?? "
    header += f"Size:{forensic_data['file_size']:,}B "
    header += f"{'MAM' if forensic_data['mam_compressed'] else 'STD'} "
    
    if forensic_data['last_execution']:
        try:
            last_exec_dt = datetime.datetime.fromisoformat(forensic_data['last_execution'].replace('T', ' '))
            header += f"Last: {last_exec_dt.strftime('%Y-%m-%d %H:%M')} "
        except:
            header += f"Last: {forensic_data['last_execution'][:16]} "
    
    header += f"Runs:{forensic_data['execution_count']}"
    
    output.append(header)
    
    # Execution timeline on one line
    if forensic_data['execution_times']:
        timeline = "  Exec: "
        for i, exec_time in enumerate(sorted(forensic_data['execution_times'], key=lambda x: x['timestamp'])[-5:]):  # Last 5
            try:
                exec_dt = datetime.datetime.fromisoformat(exec_time['timestamp'].replace('T', ' '))
                timeline += f"{exec_dt.strftime('%m/%d %H:%M')} "
            except:
                pass
        if len(forensic_data['execution_times']) > 5:
            timeline += f"(+{len(forensic_data['execution_times'])-5} more)"
        output.append(timeline)
    
    # Key DLLs on one line
    if forensic_data['loaded_dlls']:
        dll_line = f"  DLLs({len(forensic_data['loaded_dlls'])}): "
        # Show notable DLLs
        notable_dlls = [dll for dll in forensic_data['loaded_dlls'] 
                       if any(x in dll.lower() for x in ['ws2_', 'wininet', 'winhttp', 'crypt', 'bcrypt', 'dpapi'])]
        if notable_dlls:
            dll_line += f"{Color.YELLOW}" + ", ".join(notable_dlls[:5]) + f"{Color.RESET} "
        dll_line += f"+ {len(forensic_data['loaded_dlls']) - len(notable_dlls[:5])} others"
        output.append(dll_line)
    
    # Top accessed files on one line
    if forensic_data['files_accessed']:
        files_line = f"  Files({len(forensic_data['files_accessed'])}): "
        top_files = sorted(forensic_data['files_accessed'], key=lambda x: x['prefetch_count'], reverse=True)[:3]
        for f in top_files:
            fname = os.path.basename(f['filename'])
            files_line += f"{fname}({f['prefetch_count']}x) "
        if len(forensic_data['files_accessed']) > 3:
            files_line += f"+ {len(forensic_data['files_accessed'])-3} more"
        output.append(files_line)
    
    # Volumes
    if forensic_data['volumes']:
        vol_line = "  Vols: "
        for vol in forensic_data['volumes'][:2]:
            vol_line += f"{vol['path']}[{vol['serial_number']}] "
        output.append(vol_line)
    
    # Errors
    if forensic_data['parsing_errors']:
        output.append(f"  {Color.RED}Errors: {', '.join(forensic_data['parsing_errors'][:2])}{Color.RESET}")
    
    output.append("")  # Blank line between entries
    
    # Print to console
    for line in output:
        print(line)
    
    # Write to log file if specified
    if log_file:
        clean_output = []
        for line in output:
            clean_line = line
            for color in [Color.RED, Color.GREEN, Color.YELLOW, Color.BLUE, 
                         Color.MAGENTA, Color.CYAN, Color.WHITE, Color.RESET, Color.BOLD, Color.DIM]:
                clean_line = clean_line.replace(color, '')
            clean_output.append(clean_line)
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(clean_output) + '\n')

def print_forensic_report(forensic_data, detailed=False, log_file=None):
    """Print a formatted forensic report (verbose mode)"""
    output = []
    
    output.append(f"\n{Color.CYAN}{'='*80}{Color.RESET}")
    output.append(f"{Color.CYAN}=== Forensic Analysis: {forensic_data['file_name']} ==={Color.RESET}")
    output.append(f"{Color.CYAN}{'='*80}{Color.RESET}")
    output.append(f"Process: {Color.YELLOW}{forensic_data['process_name']}{Color.RESET}")
    output.append(f"Hash: {forensic_data['hash']}")
    output.append(f"Size: {forensic_data['file_size']:,} bytes")
    output.append(f"Created: {forensic_data['created']}")
    output.append(f"Modified: {forensic_data['modified']}")
    output.append(f"Version: 0x{forensic_data['version']:02X}" if forensic_data['version'] else "Version: Unknown")
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
                         Color.MAGENTA, Color.CYAN, Color.WHITE, Color.RESET, Color.BOLD, Color.DIM]:
                clean_line = clean_line.replace(color, '')
            clean_output.append(clean_line)
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(clean_output) + '\n')

def generate_execution_timeline_enhanced(all_results, log_file=None, start_date=None, end_date=None, off_hours_only=False):
    """Generate an enhanced time-sorted execution timeline optimized for wide displays"""
    # Define off-hours (11 PM to 6 AM)
    off_hours_start = 23  # 11 PM
    off_hours_end = 6     # 6 AM
    
    # Collect all executions from all files
    all_executions = []
    
    for result in all_results:
        # Get short process name without .EXE
        short_process = result['process_name']
        if short_process.upper().endswith('.EXE'):
            short_process = short_process[:-4]
            
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
                    'process': short_process,
                    'process_full': result['process_name'],
                    'file': result['file_name'],
                    'hash': result['hash'][:8] if result['hash'] else 'N/A',
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
    output.append(f"\n{Color.CYAN}{'='*180}{Color.RESET}")
    output.append(f"{Color.CYAN}{Color.BOLD}CHRONOLOGICAL EXECUTION TIMELINE - ENHANCED VIEW{Color.RESET}")
    output.append(f"{Color.CYAN}{'='*180}{Color.RESET}")
    
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
        output.append(f"{Color.YELLOW}Filters: {', '.join(filters)}{Color.RESET}")
    
    # Statistics header
    earliest = all_executions[0]['timestamp']
    latest = all_executions[-1]['timestamp']
    
    stats_line = f"Executions: {Color.GREEN}{len(all_executions)}{Color.RESET} | "
    stats_line += f"Range: {earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')} | "
    stats_line += f"Duration: {(latest - earliest).days}d {(latest - earliest).seconds // 3600}h"
    output.append(stats_line)
    
    # Count statistics
    off_hours_count = sum(1 for exe in all_executions if exe['timestamp'].hour >= off_hours_start or exe['timestamp'].hour <= off_hours_end)
    weekend_count = sum(1 for exe in all_executions if exe['timestamp'].weekday() >= 5)
    
    suspicious_processes = ['cmd', 'powershell', 'wscript', 'cscript', 'rundll32', 'mshta', 
                           'regsvr32', 'certutil', 'bitsadmin', 'msiexec', 'installutil']
    suspicious_count = sum(1 for exe in all_executions if any(s in exe['process'].lower() for s in suspicious_processes))
    
    stats_line2 = f"Off-hours: {Color.RED if off_hours_count > len(all_executions)*0.3 else Color.YELLOW}{off_hours_count}{Color.RESET} ({off_hours_count/len(all_executions)*100:.0f}%) | "
    stats_line2 += f"Weekends: {Color.YELLOW}{weekend_count}{Color.RESET} ({weekend_count/len(all_executions)*100:.0f}%) | "
    stats_line2 += f"Suspicious: {Color.RED if suspicious_count > 0 else Color.GREEN}{suspicious_count}{Color.RESET}"
    output.append(stats_line2)
    
    output.append("")
    
    # Timeline header
    header = f"{'Date':<12}{'Time':<9}{'Process':<25}{'Hash':<10}{'Flags':<30}{'Notes':<40}"
    output.append(f"{Color.DIM}{header}{Color.RESET}")
    output.append(f"{Color.DIM}{'-'*180}{Color.RESET}")
    
    # Group by date
    current_date = None
    date_exec_count = 0
    
    for exe in all_executions:
        exe_date = exe['timestamp'].date()
        
        # Date separator
        if current_date != exe_date:
            if current_date is not None and date_exec_count > 0:
                output.append(f"{Color.DIM}  └─ {date_exec_count} executions{Color.RESET}\n")
            
            current_date = exe_date
            date_exec_count = 0
            day_name = exe_date.strftime('%a')
            is_weekend = exe_date.weekday() >= 5
            
            date_str = f"{Color.BLUE}{Color.BOLD}{exe_date.strftime('%Y-%m-%d')} ({day_name})"
            if is_weekend:
                date_str += f" [WEEKEND]"
            date_str += f"{Color.RESET}"
            output.append(date_str)
        
        date_exec_count += 1
        
        # Build execution line
        time_str = exe['timestamp'].strftime('%H:%M:%S')
        hour = exe['timestamp'].hour
        is_off_hours = hour >= off_hours_start or hour <= off_hours_end
        is_suspicious = any(s in exe['process'].lower() for s in suspicious_processes)
        
        # Time coloring
        if is_off_hours:
            time_display = f"{Color.RED}{time_str}{Color.RESET}"
        else:
            time_display = time_str
        
        # Process coloring
        if is_suspicious:
            process_display = f"{Color.YELLOW}{exe['process']:<24}{Color.RESET}"
        else:
            process_display = f"{exe['process']:<24}"
        
        # Build flags
        flags = []
        if is_off_hours:
            flags.append(f"{Color.RED}OFF-HRS{Color.RESET}")
        if exe['timestamp'].weekday() >= 5:
            flags.append(f"{Color.YELLOW}WKND{Color.RESET}")
        if is_suspicious:
            flags.append(f"{Color.RED}SUSP{Color.RESET}")
        if exe['slot'] == 0:
            flags.append(f"{Color.DIM}FBACK{Color.RESET}")
        
        flags_str = ' '.join(flags)
        
        # Additional context
        notes = []
        
        # Add network DLLs if this process likely used network
        if any(net in exe['process'].lower() for net in ['browser', 'chrome', 'firefox', 'edge', 'outlook']):
            notes.append("NET")
        
        # Build the line
        line = f"  {'':<10}{time_display:<9}{process_display} {exe['hash']:<9} {flags_str:<30} {' '.join(notes):<40}"
        output.append(line)
    
    # Final date summary
    if date_exec_count > 0:
        output.append(f"{Color.DIM}  └─ {date_exec_count} executions{Color.RESET}")
    
    # Process frequency summary
    output.append(f"\n{Color.YELLOW}{Color.BOLD}TOP PROCESSES BY EXECUTION COUNT{Color.RESET}")
    output.append(f"{Color.DIM}{'-'*80}{Color.RESET}")
    
    process_counts = Counter(exe['process'] for exe in all_executions)
    max_count = max(process_counts.values()) if process_counts else 1
    
    for process, count in process_counts.most_common(15):
        bar_length = int(count * 40 / max_count)
        bar = '█' * bar_length
        
        # Check if suspicious
        is_suspicious = any(s in process.lower() for s in suspicious_processes)
        
        # Count off-hours executions for this process
        off_hours_for_process = sum(1 for exe in all_executions 
                                   if exe['process'] == process and 
                                   (exe['timestamp'].hour >= off_hours_start or exe['timestamp'].hour <= off_hours_end))
        
        if is_suspicious:
            line = f"{Color.YELLOW}{process:<25}{Color.RESET} {count:>4} "
        else:
            line = f"{process:<25} {count:>4} "
        
        line += f"{Color.BLUE}{bar}{Color.RESET}"
        
        if off_hours_for_process > 0:
            line += f" {Color.RED}({off_hours_for_process} off-hrs){Color.RESET}"
        
        output.append(line)
    
    # Hourly heatmap
    output.append(f"\n{Color.YELLOW}{Color.BOLD}HOURLY ACTIVITY HEATMAP{Color.RESET}")
    output.append(f"{Color.DIM}{'-'*80}{Color.RESET}")
    
    hourly_counts = Counter(exe['timestamp'].hour for exe in all_executions)
    max_hourly = max(hourly_counts.values()) if hourly_counts else 1
    
    # Create visual heatmap
    for hour in range(24):
        count = hourly_counts.get(hour, 0)
        heat_level = int(count * 50 / max_hourly) if max_hourly > 0 else 0
        
        # Create heat bar
        if hour >= off_hours_start or hour <= off_hours_end:
            bar_color = Color.RED
            time_color = Color.RED
        else:
            bar_color = Color.GREEN
            time_color = Color.RESET
        
        bar = '▓' * heat_level + '░' * (50 - heat_level)
        
        output.append(f"{time_color}{hour:02d}:00{Color.RESET} │{bar_color}{bar}{Color.RESET}│ {count:>3}")
    
    # Rapid burst detection
    output.append(f"\n{Color.YELLOW}{Color.BOLD}EXECUTION BURST ANALYSIS{Color.RESET}")
    output.append(f"{Color.DIM}{'-'*80}{Color.RESET}")
    
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
        output.append(f"{Color.RED}Found {len(bursts)} rapid execution burst(s):{Color.RESET}")
        
        for i, burst in enumerate(sorted(bursts, key=lambda x: x['count'], reverse=True)[:5]):
            burst_processes = Counter(e['process'] for e in burst['executions'])
            
            output.append(f"\n  Burst #{i+1}: {Color.RED}{burst['count']} executions in {burst['duration']:.0f}s{Color.RESET}")
            output.append(f"    Time: {burst['start'].strftime('%Y-%m-%d %H:%M:%S')}")
            output.append(f"    Processes: {', '.join(f'{p}({c})' for p, c in burst_processes.most_common())}")
            
            if burst['start'].hour >= off_hours_start or burst['start'].hour <= off_hours_end:
                output.append(f"    {Color.RED}⚠ OCCURRED DURING OFF-HOURS{Color.RESET}")
    else:
        output.append("No rapid execution bursts detected.")
    
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
                             Color.MAGENTA, Color.CYAN, Color.WHITE, Color.RESET, Color.BOLD, Color.DIM]:
                    clean_line = clean_line.replace(color, '')
                f.write(clean_line + '\n')

def main():
    Color.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(description='Advanced Prefetch Forensic Analyzer - Enhanced Display')
    parser.add_argument('prefetch_file', nargs='?', help='Specific prefetch file to analyze')
    parser.add_argument('--all', action='store_true', help='Analyze all prefetch files')
    parser.add_argument('--path', default=r'C:\Windows\Prefetch', help='Prefetch directory path')
    parser.add_argument('--output', help='Output JSON file for results')
    parser.add_argument('--detailed', action='store_true', help='Show detailed file lists')
    parser.add_argument('--process', help='Filter by process name')
    parser.add_argument('--suspicious', action='store_true', help='Analyze only suspicious processes')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output (original format)')
    parser.add_argument('--summary-only', action='store_true', help='Show only summary statistics')
    parser.add_argument('--log', help='Log all output to file (in addition to console)')
    parser.add_argument('--no-timeline', action='store_true', help='Skip the execution timeline')
    parser.add_argument('--start-date', help='Start date for timeline filter (YYYY-MM-DD)')
    parser.add_argument('--end-date', help='End date for timeline filter (YYYY-MM-DD)')
    parser.add_argument('--off-hours-only', action='store_true', help='Show only off-hours executions in timeline')
    
    args = parser.parse_args()
    
    if not args.prefetch_file and not args.all:
        parser.error("Specify a prefetch file or use --all to analyze all files")
    
    print(f"{Color.CYAN}{Color.BOLD}Advanced Prefetch Forensic Analyzer - Enhanced Display{Color.RESET}")
    print(f"Optimized for wide terminal displays | Use --verbose for detailed output\n")
    
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
            f.write(f"Prefetch Analysis Report\n")
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
            print(f"\n{Color.YELLOW}Analyzing {len(files_to_analyze)} files - using compact display format{Color.RESET}")
            print("Options:")
            print("  --verbose       : Use original detailed format")
            print("  --summary-only  : Show summary statistics only")
            print("  --suspicious    : Analyze only suspicious processes")
            print(f"\n{Color.CYAN}Analysis will be saved to: {log_file if log_file else 'auto-generated file'}{Color.RESET}\n")
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
        
        analyzer = PrefetchForensics(pf_file, verbose=args.verbose)
        forensic_data = analyzer.parse()
        
        # Choose display format based on verbose flag
        if not args.summary_only:
            if args.verbose or len(files_to_analyze) == 1:
                # Use original verbose format for single files or when --verbose is specified
                print_forensic_report(forensic_data, detailed=args.detailed, log_file=log_file)
            else:
                # Use new compact format for multiple files
                print_forensic_report_compact(forensic_data, log_file=log_file)
        
        all_results.append(forensic_data)
        
        # Track failed files
        if forensic_data['parsing_errors']:
            failed_files.append(os.path.basename(pf_file))
    
    if args.summary_only and len(files_to_analyze) > 1:
        print(f"\rProcessed all {len(files_to_analyze)} files successfully!                    ")
    
    # Summary statistics for multiple files
    if len(files_to_analyze) > 1:
        summary = []
        summary.append(f"\n{Color.YELLOW}{Color.BOLD}{'='*80}{Color.RESET}")
        summary.append(f"{Color.YELLOW}{Color.BOLD}FINAL SUMMARY STATISTICS{Color.RESET}")
        summary.append(f"{Color.YELLOW}{'='*80}{Color.RESET}")
        
        summary.append(f"Total files analyzed: {Color.GREEN}{len(all_results)}{Color.RESET}")
        
        # Count MAM compressed files
        mam_count = sum(1 for r in all_results if r['mam_compressed'])
        summary.append(f"MAM compressed: {Color.CYAN}{mam_count}{Color.RESET} ({mam_count/len(all_results)*100:.0f}%)")
        
        # Files with successful timestamp extraction
        files_with_times = sum(1 for r in all_results if r['execution_times'])
        summary.append(f"With timestamps: {Color.GREEN}{files_with_times}{Color.RESET} ({files_with_times/len(all_results)*100:.0f}%)")
        
        # Files with DLLs and file references
        files_with_dlls = sum(1 for r in all_results if r['loaded_dlls'])
        files_with_refs = sum(1 for r in all_results if r['files_accessed'])
        summary.append(f"With DLL info: {Color.GREEN}{files_with_dlls}{Color.RESET} | With file refs: {Color.GREEN}{files_with_refs}{Color.RESET}")
        
        total_executions = sum(len(r['execution_times']) for r in all_results)
        summary.append(f"Total executions: {Color.GREEN}{total_executions}{Color.RESET}")
        
        total_files_accessed = sum(len(r['files_accessed']) for r in all_results)
        summary.append(f"Total file refs: {total_files_accessed:,}")
        
        all_dlls = set()
        for r in all_results:
            all_dlls.update(r['loaded_dlls'])
        summary.append(f"Unique DLLs: {len(all_dlls)}")
        
        parsing_errors = sum(1 for r in all_results if r['parsing_errors'])
        if parsing_errors > 0:
            summary.append(f"Parse errors: {Color.RED}{parsing_errors}{Color.RESET} ({parsing_errors/len(all_results)*100:.0f}%)")
        
        # Top processes by file count
        process_file_counts = Counter(r['process_name'] for r in all_results)
        summary.append(f"\n{Color.CYAN}Top Processes by Prefetch Files:{Color.RESET}")
        for proc, count in process_file_counts.most_common(10):
            # Get execution count for this process
            exec_count = sum(len(r['execution_times']) for r in all_results if r['process_name'] == proc)
            summary.append(f"  {proc:<30} {count:>3} files, {exec_count:>4} executions")
        
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
                                 Color.MAGENTA, Color.CYAN, Color.WHITE, Color.RESET, Color.BOLD, Color.DIM]:
                        clean_line = clean_line.replace(color, '')
                    f.write(clean_line + '\n')
    
    # Generate execution timeline (enhanced version)
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
                    
            generate_execution_timeline_enhanced(all_results, log_file, start_date, end_date, args.off_hours_only)
    
    # Export results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n{Color.GREEN}JSON results exported to: {args.output}{Color.RESET}")
    
    # Final message
    if log_file:
        print(f"\n{Color.GREEN}{Color.BOLD}Complete analysis saved to: {log_file}{Color.RESET}")
        print(f"Contains forensic data for {len(all_results)} files with {sum(len(r['execution_times']) for r in all_results)} total executions")

if __name__ == "__main__":
    main()
