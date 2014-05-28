# FileInfo v1.0
# twitter: @bbaskin 
# email: brian [[AT]] thebaskins.com

import ctypes
import hashlib
import os
import pefile
import struct
import subprocess
import sys
import time
try:
    import yara # Install from src, not pip
    use_yara = True
except ImportError:
    use_yara = False

from traceback import format_exc

FILE_GNUWIN32 = True

__VERSION__ = '1.0'
FIELD_SIZE = 16
FILE_SUFFIX = '.info.txt'
YARA_SIG_FOLDER = ''
SCRIPT_PATH = ''

def open_file_with_assoc(fname):
    """
    Opens the specified file with its associated application

    Arguments:
        fname: full path to a file to open
    Results:
        None
    """
    if os.name == 'mac':
        subprocess.call(('open', fname))
    elif os.name == 'nt':
        os.startfile(fname)
    elif os.name == 'posix':
        subprocess.call(('open', fname))


def file_exists(fname):
    """
    Determine if a file exists

    Arguments:
        fname: path to a file
    Results:
        boolean value if file exists
    """
    return os.path.exists(fname) and os.access(fname, os.X_OK)


def search_exe(fname):
    """
    Finds the local path to specified executable

    Arguments:
        None
    Results:
        folder path to specified executable
    """
    if file_exists(fname):
        return fname
    else:
        for path in os.environ['PATH'].split(os.pathsep):
            if file_exists(os.path.join(path.strip('"'), fname)):
                return os.path.join(path, fname)


def yara_import_rules(yara_folder):
    """
    Import a folder of YARA rule files

    Arguments:
        yara_folder: path to folder containing rules
    Results:
        rules: a yara.Rules structure of available YARA rules
    """
    yara_files = {}
    if not yara_folder[-1] == '\\':
        yara_folder += '\\'
    print('[*] Loading YARA rules from folder: %s' % yara_folder)
    files = os.listdir(yara_folder)
    for file_name in files:
        if '.yara' in file_name:
            yara_files[file_name.split('.yara')[0]] = yara_folder + file_name

    if not yara_files:
        return 

    try:
        rules = yara.compile(filepaths=yara_files)
        print('[*] YARA rules loaded. Total files imported: %d' % len(yara_files))
    except yara.SyntaxError:
        print('[!] Syntax error found in one of the imported YARA files. Error shown below.')
        rules = ''
        yara_rule_check(yara_folder)
        print('[!] YARA rules disabled until all Syntax Errors are fixed.')
    return rules

    
def yara_rule_check(yara_folder):
    """
    Scan a folder of YARA rule files to determine which provide syntax errors

    Arguments:
        yara_folder: path to folder containing rules
    """
    for name in os.listdir(yara_folder):
        fname = yara_folder + name
        try:
            rules = yara.compile(filepath=fname)
        except yara.SyntaxError:
            print('[!] YARA Syntax Error in file: %s' % fname)
            print(format_exc())


def yara_scan(fname):
    """
    Scan a specified file name with YARA rules. If YARA_SIG_FOLDER isn't set
    then default to <ScriptDir>\YARA
    This should be rewritten to load once, scan many.

    Arguments:
        fname: path of file to scan
    """
    global YARA_SIG_FOLDER
    yara_rules = []
    result = []
    
    if not YARA_SIG_FOLDER:
        YARA_SIG_FOLDER = os.path.join(SCRIPT_PATH, 'YARA')
    if os.path.isdir(YARA_SIG_FOLDER):
        yara_rules = yara_import_rules(YARA_SIG_FOLDER)

    if yara_rules:
        yara_hits = yara_rules.match(fname)
        return yara_hits
    else:
        return


def get_magic(fileName):
    """
    Retrieve file type through python-magic, or alternative
    
    Arguments:
        fileName: path to file name
    """
    # The following require libmagic, which is a PITA in Windows
    #import magic
    #m = magic.open(magic.MAGIC_MIME)
    #m.load()
    #return m.file(fileName)

    file_exe = search_exe('file.exe')
    if not file_exe:
        return 'Error: file.exe not found'
    
    magic_path = os.path.split(file_exe)[0]
    envs = dict(os.environ)
    envs['CYGWIN'] = 'nodosfilewarning'
    if FILE_GNUWIN32:
        cmdline = '"%s" -b "%s"' % (file_exe, fileName)
    else:
        cmdline = '"%s" -b -m "%s" "%s"' % (file_exe, magic_path + '\\magic.mgc', fileName)
    
    output = subprocess.Popen(cmdline, stdout=subprocess.PIPE, env=envs).communicate()[0]
    if output:
        return output.strip()
    return 'Unknown error'


def get_signsrch(fileName):
    """
    Retrieve signatures type through signsrch
    
    Arguments:
        fileName: path to file name
    """
    signsrch_exe = search_exe('signsrch.exe')
    if not signsrch_exe:
        return ''
    
    cmdline = '"%s" -e "%s"' % (signsrch_exe, fileName)
    output = subprocess.Popen(cmdline, stdout=subprocess.PIPE).communicate()[0]
    if not output:
        return ''
    sigs = list()
    for i in output.split('\r\n'):
        if i.startswith('- ') or len(i.strip()) < 20:
            continue
        sigs.append(i.strip())
    return sigs
    
    
def get_fuzzy(data):
    """
    Uses SSDeep's fuzzy.dll to return a fuzzy hash for a block of data
    Based off of http://codepaste.ru/13245/

    Arguments:
        data: binary data to perform hash of
    """
    fuzzy_dll = 'fuzzy.dll'
    error_code = 0
    
    try:
        fuzzy = ctypes.CDLL(fuzzy_dll)
    except WindowsError, error:
        error = str(error)
        if '[Error ' in error:
            error_code = error.split()[1].split(']')[0]
    if error_code:
        if error_code == '193':
            py_bits = struct.calcsize('P') * 8
            return '!!! %s incompatible. Needs to be same as Python: %d-bits' % (fuzzy_dll, py_bits)
        elif error_code == '126':
            return '!!! %s not found' % fuzzy_dll
        else:
            return '!!! %s not loaded. Unknown error.'
        return

    out_buf = ctypes.create_string_buffer('\x00' * 1024)
    fuzzy.fuzzy_hash_buf(data, len(data), out_buf)
    return out_buf.value


def check_overlay(data):
    """
    Performs cursory checks against overlay data to determine if it's of a known type.
    Currently just digital signatures
    
    Arguments:
        data: overlay data
    """
    if not len(data):
        return
    if len(data) > 4:
        #Check for Authenticode 0x00020200
        test_size = struct.unpack('l', data[0:4])[0]
        if test_size == len(data) and test_size > 512:
            hdr1 = struct.unpack('l', data[4:8])[0]
            if hdr1 == 0x00020200:
                return '(Authenticode Signature)'

    
def CheckFile(fileName, outfile):
    """
    Main routine to scan a file
    
    Arguments:
        fileName: path to file name
        outfile: output file to write results to
    """
    data = open(fileName, 'rb').read()
    (fpath, fname) = os.path.split(fileName)

    outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'File Name', fname))
    outfile.write('%-*s: %s bytes\n' % (FIELD_SIZE, 'File Size', '{:,}'.format(os.path.getsize(fileName))))
    outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'MD5', hashlib.md5(data).hexdigest()))
    outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'SHA1', hashlib.sha1(data).hexdigest()))

    # Get Fuzzy hash, requires ssdeep's fuzzy.dll
    fuzzy = get_fuzzy(data)
    if fuzzy: 
        outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'Fuzzy', fuzzy))

    # Do executable scans
    pe = None
    try:
        pe = pefile.PE(fileName, fast_load=True)
    except:
        print '!!! Not a valid executable'
    if pe:
        try:
            time_output = '%s UTC' % time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp))
        except:
            time_output = 'Invalid Time'
        outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'Compiled Time', time_output))

        section_hdr = 'PE Sections (%d)' % pe.FILE_HEADER.NumberOfSections
        section_hdr2 = '%-10s %-10s %s' % ('Name', 'Size', 'MD5')
        outfile.write('%-*s: %s\n' % (FIELD_SIZE, section_hdr, section_hdr2))
        for section in pe.sections:
            section_name = section.Name.strip('\x00')
            outfile.write('%-*s %-10s %-10s %s\n' % (FIELD_SIZE + 1, ' ', section_name, 
                                                     '{:,}'.format(section.SizeOfRawData), 
                                                     section.get_hash_md5()))

        EoD = pe.sections[-1]
        end_of_PE = (EoD.PointerToRawData + EoD.SizeOfRawData)
        overlay_len = len(data) - end_of_PE
        if overlay_len:
            overlay = data[end_of_PE:len(data)]
            overlay_type = check_overlay(overlay)
            outfile.write('%-*s+ %-10s %-10s %s %s\n' % (FIELD_SIZE, ' ', 
                                                        hex(end_of_PE), '{:,}'.format((len(overlay))),
                                                        hashlib.md5(overlay).hexdigest(),
                                                        overlay_type))
        if pe.is_dll():
            #DLL, get original compiled name and export routines
            #Load in export directory 
            pe.parse_data_directories( directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

            orig_name = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
            outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'Original DLL', orig_name))

            section_hdr = 'DLL Exports (%d)' %len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            section_hdr2 = '%-8s %s' % ('Ordinal', 'Name')
            outfile.write('%-*s: %s\n' % (FIELD_SIZE, section_hdr, section_hdr2))
            
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
              outfile.write('%-*s %-8s %s\n' % (FIELD_SIZE + 1, ' ', exp.ordinal, exp.name)) 
        if pe.is_driver():
            #TODO
            raise
            
    if use_yara:
        yarahits = yara_scan(fileName)
        if yarahits:
            for match in yarahits:
                outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'YARA', match))

    # Search for signatures with signsrch
    outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'Magic', get_magic(fileName)))
    signsrch_sigs = get_signsrch(fileName)
    if signsrch_sigs:
        outfile.write('%-*s: %s\n' % (FIELD_SIZE, 'SignSrch', signsrch_sigs[0]))
        for i in range(2, len(signsrch_sigs)):
            outfile.write('%-*s  %s\n' % (FIELD_SIZE, ' ', signsrch_sigs[i]))

    return 


def main():
    global SCRIPT_PATH
    SCRIPT_PATH = os.path.split(sys.argv[0])[0] # Keep this to find YARA folder
    
    try:
        fileName = sys.argv[1]
    except IndexError:
        print 'FileInfo v%s\n' % __VERSION__
        print 'Usage:\n %s <file>' % (sys.argv[0])
        quit()

    if not os.path.isfile(fileName):
        quit()

    outputfile = fileName + FILE_SUFFIX
    outfile = open(outputfile, 'w')
        
    CheckFile(fileName, outfile)

    outfile.close()
    open_file_with_assoc(outputfile)

if __name__ == "__main__":
    main()