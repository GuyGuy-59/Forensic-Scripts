#!/bin/bash


# Forensic Collector for Windows - Forensic artifact extraction script
# Description: Extracts Windows system artifacts from a disk image


set -euo pipefail  # Exit on error, undefined variables, pipe errors

# Configuration
readonly SCRIPT_NAME="Forensic Collector Win"
readonly SCRIPT_VERSION="2.0"
readonly REQUIRED_TOOLS=("mmls" "icat" "fls" "tsk_recover" "xxd" "dd" "md5sum")

# Individual files searched by name (path preserved in output)
readonly ARTEFACT_FILES=(
    'System32/config/SYSTEM'   'System32/config/SECURITY'
    'System32/config/SAM'      'System32/config/SOFTWARE'
    'NTUSER.DAT'               'USRCLASS.DAT'
    'pagefile.sys'             'hiberfil.sys'
    'setupapi.dev.log'         'SchedLgU.txt'
    'hosts'
)

# Directories collected entirely (all files under each path)
readonly ARTEFACT_DIRS=(
    'Windows/Prefetch'
    'Windows/Tasks'
    'Windows/System32/Tasks'
    'Windows/System32/sru'
    'Windows/System32/winevt/Logs'
    'Windows/System32/Logfiles/W3SVC1'
    'Windows/appcompat/Programs'
    '$Recycle.Bin'
)
readonly ENCRYPTED_SIGNATURE="eb58 902d 4656 452d 4653 2d00 0208 0000"

# Global variables
directory_case=""
directory_icat=""
directory_tsk_recover=""
evidence_file=""
offsetevidence=""
fls_output=""
log_file=""


# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ -n "$log_file" ]]; then
        echo "[$timestamp] [$level] $message" | tee -a "$log_file"
    else
        echo "[$timestamp] [$level] $message"
    fi
}

log_info() {
    log "INFO" "$@"
}

log_error() {
    log "ERROR" "$@" >&2
}

log_warning() {
    log "WARNING" "$@"
}

log_success() {
    log "SUCCESS" "$@"
}

# Help function
show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION

Usage: $0 [OPTIONS]

Options:
    -h, --help          Display this help message
    -v, --version       Display script version
    -d, --directory DIR Specify case directory (avoids interactive input)
    -e, --evidence FILE Specify evidence file (avoids interactive input)
    -o, --offset OFFSET Specify partition offset (avoids interactive input)

Description:
    This script extracts Windows forensic artifacts from a disk image
    using SleuthKit (TSK) tools.

Examples:
    $0
    $0 -d "Case001" -e "/path/to/image.dd" -o 2048
EOF
}

# Check requirements
check_requirements() {
    log_info "Checking requirements..."
    local missing_requirements=()

    for requirement in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$requirement" &> /dev/null; then
            missing_requirements+=("$requirement")
        fi
    done

    if [[ ${#missing_requirements[@]} -gt 0 ]]; then
        log_error "The following tools are not installed: ${missing_requirements[*]}"
        log_error "Please install SleuthKit (TSK) and required system tools."
        exit 1
    fi

    log_success "All requirements are installed"
}

# Create directories
create_directories() {
    if [[ -z "$directory_case" ]]; then
        read -p "Case directory name: " directory_case
    fi

    if [[ -z "$directory_case" ]]; then
        log_error "Case directory name cannot be empty"
        exit 1
    fi

    # Clean directory name (remove dangerous characters)
    directory_case=$(echo "$directory_case" | tr -d '/\\:*?"<>|' | tr ' ' '_')

    directory_icat="$directory_case/result_icat"
    directory_tsk_recover="$directory_case/result_tsk_recover"
    log_file="$directory_case/forensic_collector.log"

    if ! mkdir -p "$directory_case" "$directory_icat" "$directory_tsk_recover" 2>/dev/null; then
        log_error "Cannot create directories: $directory_case"
        exit 1
    fi

    fls_output="$directory_icat/fls_output.txt"
    
    # Initialize log file
    echo "=== $SCRIPT_NAME v$SCRIPT_VERSION - Session started ===" > "$log_file"
    log_info "Directories created: $directory_case"
    log_info "icat directory: $directory_icat"
    log_info "tsk_recover directory: $directory_tsk_recover"
}

# Get evidence file
get_evidence_file() {
    if [[ -z "$evidence_file" ]]; then
        read -p "Evidence file path: " evidence_file
    fi

    if [[ -z "$evidence_file" ]]; then
        log_error "Evidence file path cannot be empty"
        exit 1
    fi

    # Expand path (support for ~)
    evidence_file="${evidence_file/#\~/$HOME}"

    if [[ ! -f "$evidence_file" ]]; then
        log_error "Evidence file does not exist: $evidence_file"
        exit 1
    fi

    if [[ ! -r "$evidence_file" ]]; then
        log_error "Evidence file is not readable: $evidence_file"
        exit 1
    fi

    log_success "Evidence file found: $evidence_file"
    log_info "Calculating MD5 hash of evidence file..."
    
    if md5sum "$evidence_file" >> "$directory_case/md5sum.txt" 2>>"$log_file"; then
        log_success "MD5 hash calculated and saved"
    else
        log_warning "Failed to calculate MD5 hash"
    fi
}

# Convert evidence file to raw if format is not natively supported by TSK
convert_to_raw() {
    # Detect format by extension then by file magic
    local format=""
    case "${evidence_file,,}" in
        *.vmdk)  format="vmdk"  ;;
        *.vhd)   format="vhd"   ;;
        *.vhdx)  format="vhdx"  ;;
        *.vdi)   format="vdi"   ;;
        *.qcow2) format="qcow2" ;;
        *.qcow)  format="qcow"  ;;
    esac

    if [[ -z "$format" ]]; then
        local file_magic
        file_magic=$(file -b "$evidence_file" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        [[ "$file_magic" =~ vmware ]] && format="vmdk"
    fi

    if [[ -z "$format" ]]; then
        log_info "Image appears to be raw format — no conversion needed"
        return 0
    fi

    log_info "Non-standard format detected: $format — conversion to raw required"

    local raw_path="${evidence_file%.*}.raw"

    if [[ -f "$raw_path" ]]; then
        log_info "Raw image already exists: $raw_path — skipping conversion"
        evidence_file="$raw_path"
        return 0
    fi

    # Disk space check (parse "X bytes" from qemu-img info plain output)
    if command -v qemu-img &> /dev/null; then
        local virtual_size_bytes available_bytes
        virtual_size_bytes=$(qemu-img info "$evidence_file" 2>/dev/null \
            | grep "virtual size" | grep -oE '\([0-9]+ bytes\)' | grep -oE '[0-9]+')
        available_bytes=$(df --output=avail -B1 "$(dirname "$raw_path")" 2>/dev/null | tail -1 | tr -d ' ')
        if [[ -n "$virtual_size_bytes" && -n "$available_bytes" ]] && (( virtual_size_bytes > available_bytes )); then
            log_error "Not enough disk space: need ${virtual_size_bytes} bytes, ${available_bytes} available"
            exit 1
        fi
    fi

    if ! command -v qemu-nbd &> /dev/null; then
        log_error "qemu-nbd not found — cannot convert $format image (install qemu-utils)"
        exit 1
    fi

    # Load nbd kernel module
    modprobe nbd max_part=8 2>/dev/null || true

    # Find a free nbd device
    local nbd_dev=""
    for i in $(seq 0 15); do
        if [[ -b "/dev/nbd${i}" ]] && [[ ! -f "/sys/class/block/nbd${i}/pid" ]]; then
            nbd_dev="/dev/nbd${i}"
            break
        fi
    done

    if [[ -z "$nbd_dev" ]]; then
        log_error "No free nbd device found"
        exit 1
    fi

    log_info "Attaching $format image to $nbd_dev..."
    if ! qemu-nbd -r -c "$nbd_dev" "$evidence_file" 2>>"$log_file"; then
        log_error "Failed to attach image to $nbd_dev"
        exit 1
    fi

    log_info "Converting to raw with dd (this may take a while)..."
    local dd_exit=0
    dd if="$nbd_dev" of="$raw_path" bs=4M status=progress 2>>"$log_file" || dd_exit=$?

    qemu-nbd -d "$nbd_dev" 2>>"$log_file"

    if [[ $dd_exit -ne 0 ]]; then
        log_error "dd conversion failed"
        rm -f "$raw_path"
        exit 1
    fi

    log_success "Conversion completed: $raw_path"
    evidence_file="$raw_path"
    log_info "Calculating MD5 hash of converted raw image..."
    if md5sum "$evidence_file" >> "$directory_case/md5sum.txt" 2>>"$log_file"; then
        log_info "MD5 hash saved for raw image"
    fi
}

# Display partition layout
display_partition_layout() {
    log_info "Displaying partition layout..."
    echo ""
    echo "=== Partition Layout ==="
    if mmls "$evidence_file" 2>>"$log_file"; then
        echo ""
        log_success "Partition layout displayed"
    else
        log_error "Error displaying partition layout"
        exit 1
    fi
}

# Check if file is encrypted
check_encryption() {
    local offset="$1"
    log_info "Checking encryption at offset $offset..."
    
    local xxd_output
    if ! xxd_output=$(dd if="$evidence_file" bs=1 skip="$offset" count=16 2>/dev/null | xxd -l 16 2>/dev/null); then
        log_error "Cannot read file at specified offset"
        return 1
    fi

    if [[ "$xxd_output" =~ $ENCRYPTED_SIGNATURE ]]; then
        log_error "Evidence file appears to be encrypted (BitLocker detected)"
        return 1
    fi

    log_success "File does not appear to be encrypted"
    return 0
}

# Extract artifacts
# Extract one file from a fls output line, preserving directory structure
extract_from_line() {
    local fls_line="$1"

    # Skip directory entries
    [[ "${fls_line:0:3}" == "d/d" ]] && return 0

    local inode full_path
    inode=$(echo "$fls_line" | awk '{print $2}' | cut -d ':' -f 1)
    full_path=$(echo "$fls_line" | sed 's/^[^:]*:[[:space:]]*//')

    [[ ! "$inode" =~ ^[0-9]+-[0-9]+-[0-9]+$ ]] && return 0
    [[ -z "$full_path" ]] && return 0

    local dest_file="$directory_icat/$full_path"
    mkdir -p "$(dirname "$dest_file")" 2>/dev/null

    if icat -o "$offsetevidence" "$evidence_file" "$inode" > "$dest_file" 2>>"$log_file"; then
        log_success "Extracted: $full_path (inode: $inode)"
        md5sum "$dest_file" >> "$directory_icat/md5sum.txt" 2>>"$log_file" || true
        return 0
    else
        log_warning "Failed: $full_path"
        rm -f "$dest_file"
        return 1
    fi
}

extract_artefacts() {
    if [[ -z "$offsetevidence" ]]; then
        read -p "First system partition offset: " offsetevidence
    fi

    if [[ -z "$offsetevidence" ]]; then
        log_error "Offset cannot be empty"
        exit 1
    fi

    if ! [[ "$offsetevidence" =~ ^[[:digit:]]+$ ]]; then
        log_error "Offset must be an integer: $offsetevidence"
        exit 1
    fi

    log_info "Partition offset: $offsetevidence"

    if ! check_encryption "$offsetevidence"; then
        exit 1
    fi

    # Extract NTFS metadata files by fixed inode
    log_info 'Extracting NTFS metadata ($MFT, $LogFile)...'
    for meta in "0:MFT" "2:LogFile"; do
        local meta_inode="${meta%%:*}" meta_name="${meta##*:}"
        if icat -o "$offsetevidence" "$evidence_file" "$meta_inode" > "$directory_icat/$meta_name" 2>>"$log_file"; then
            log_success "$meta_name extracted (inode $meta_inode)"
            md5sum "$directory_icat/$meta_name" >> "$directory_icat/md5sum.txt" 2>>"$log_file" || true
        else
            [[ "$meta_inode" == "0" ]] && { log_error "Failed to extract MFT"; exit 1; }
            log_warning "Failed to extract $meta_name"
        fi
    done

    # Build filesystem listing once (fls -r is expensive)
    local fls_full="$directory_icat/fls_full.txt"
    log_info "Building full filesystem listing (fls -r)..."
    fls -r -o "$offsetevidence" "$evidence_file" > "$fls_full" 2>>"$log_file" || true

    if [[ ! -s "$fls_full" ]]; then
        log_error "fls listing is empty — cannot extract artifacts"
        exit 1
    fi
    log_success "Filesystem listing: $(wc -l < "$fls_full") entries"

    local extracted_count=0 failed_count=0

    # Extract individual files (by name, path preserved in output)
    log_info "Extracting individual artifacts..."
    for artefact in "${ARTEFACT_FILES[@]}"; do
        local matches
        matches=$(grep -i "$artefact" "$fls_full" 2>/dev/null || true)
        [[ -z "$matches" ]] && continue
        while IFS= read -r line; do
            if extract_from_line "$line"; then ((extracted_count++)) || true
            else ((failed_count++)) || true; fi
        done <<< "$matches"
    done

    # Extract directories entirely (all files under each path)
    log_info "Extracting directory artifacts..."
    for artefact_dir in "${ARTEFACT_DIRS[@]}"; do
        local dir_matches
        dir_matches=$(grep -i "${artefact_dir}/" "$fls_full" 2>/dev/null || true)
        if [[ -z "$dir_matches" ]]; then
            log_warning "Directory not found: $artefact_dir"
            continue
        fi
        local dir_count=0
        log_info "Collecting: $artefact_dir"
        while IFS= read -r line; do
            if extract_from_line "$line"; then
                ((extracted_count++)) || true; ((dir_count++)) || true
            else
                ((failed_count++)) || true
            fi
        done <<< "$dir_matches"
        log_info "  -> $dir_count files extracted from $artefact_dir"
    done

    log_info "Extraction completed: $extracted_count files extracted, $failed_count failures"

    # Full dump with tsk_recover
    log_info "Full extraction with tsk_recover..."
    if tsk_recover -a -o "$offsetevidence" "$evidence_file" "$directory_tsk_recover" >>"$log_file" 2>&1; then
        log_success "tsk_recover extraction completed: $directory_tsk_recover"
    else
        log_warning "Issues encountered during tsk_recover extraction (see log)"
    fi
}

# Display summary
show_summary() {
    echo ""
    echo "=== Extraction Summary ==="
    echo "Case directory: $directory_case"
    echo "Evidence file: $evidence_file"
    echo "Offset used: $offsetevidence"
    echo ""
    echo "Files extracted with icat: $directory_icat"
    echo "Files extracted with tsk_recover: $directory_tsk_recover"
    echo "Log file: $log_file"
    echo ""
    
    if [[ -f "$directory_icat/md5sum.txt" ]]; then
        local hash_count
        hash_count=$(wc -l < "$directory_icat/md5sum.txt" | tr -d ' ')
        echo "Number of files with MD5 hash: $hash_count"
    fi
    
    log_info "Extraction completed successfully"
}



parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            -d|--directory)
                directory_case="$2"
                shift 2
                ;;
            -e|--evidence)
                evidence_file="$2"
                shift 2
                ;;
            -o|--offset)
                offsetevidence="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}


main() {
    parse_arguments "$@"
    
    echo "=== $SCRIPT_NAME v$SCRIPT_VERSION ==="
    echo ""
    
    check_requirements
    create_directories
    get_evidence_file
    convert_to_raw
    display_partition_layout
    extract_artefacts
    show_summary
    
    echo ""
    log_success "Script completed successfully"
}

# Execute main script
main "$@"#!/bin/bash


# Forensic Collector for Windows - Forensic artifact extraction script
# Description: Extracts Windows system artifacts from a disk image


set -euo pipefail  # Exit on error, undefined variables, pipe errors

# Configuration
readonly SCRIPT_NAME="Forensic Collector Win"
readonly SCRIPT_VERSION="2.0"
readonly REQUIRED_TOOLS=("mmls" "icat" "fls" "tsk_recover" "xxd" "dd" "md5sum")
readonly ARTEFACT_ARRAY=("SYSTEM" "SECURITY" "SAM" "SOFTWARE" "NTUSER.DAT" "pagefile.sys" "Setup.evtx" "System.evtx" "Security.evtx" "Parameters.evtx" "Application.evtx")
readonly ENCRYPTED_SIGNATURE="eb58 902d 4656 452d 4653 2d00 0208 0000"

# Global variables
directory_case=""
directory_icat=""
directory_tsk_recover=""
evidence_file=""
offsetevidence=""
fls_output=""
log_file=""


# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$log_file"
}

log_info() {
    log "INFO" "$@"
}

log_error() {
    log "ERROR" "$@" >&2
}

log_warning() {
    log "WARNING" "$@"
}

log_success() {
    log "SUCCESS" "$@"
}

# Help function
show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION

Usage: $0 [OPTIONS]

Options:
    -h, --help          Display this help message
    -v, --version       Display script version
    -d, --directory DIR Specify case directory (avoids interactive input)
    -e, --evidence FILE Specify evidence file (avoids interactive input)
    -o, --offset OFFSET Specify partition offset (avoids interactive input)

Description:
    This script extracts Windows forensic artifacts from a disk image
    using SleuthKit (TSK) tools.

Examples:
    $0
    $0 -d "Case001" -e "/path/to/image.dd" -o 2048
EOF
}

# Check requirements
check_requirements() {
    log_info "Checking requirements..."
    local missing_requirements=()

    for requirement in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$requirement" &> /dev/null; then
            missing_requirements+=("$requirement")
        fi
    done

    if [[ ${#missing_requirements[@]} -gt 0 ]]; then
        log_error "The following tools are not installed: ${missing_requirements[*]}"
        log_error "Please install SleuthKit (TSK) and required system tools."
        exit 1
    fi

    log_success "All requirements are installed"
}

# Create directories
create_directories() {
    if [[ -z "$directory_case" ]]; then
        read -p "Case directory name: " directory_case
    fi

    if [[ -z "$directory_case" ]]; then
        log_error "Case directory name cannot be empty"
        exit 1
    fi

    # Clean directory name (remove dangerous characters)
    directory_case=$(echo "$directory_case" | tr -d '/\\:*?"<>|' | tr ' ' '_')

    directory_icat="$directory_case/result_icat"
    directory_tsk_recover="$directory_case/result_tsk_recover"
    log_file="$directory_case/forensic_collector.log"

    if ! mkdir -p "$directory_case" "$directory_icat" "$directory_tsk_recover" 2>/dev/null; then
        log_error "Cannot create directories: $directory_case"
        exit 1
    fi

    fls_output="$directory_icat/fls_output.txt"
    
    # Initialize log file
    echo "=== $SCRIPT_NAME v$SCRIPT_VERSION - Session started ===" > "$log_file"
    log_info "Directories created: $directory_case"
    log_info "icat directory: $directory_icat"
    log_info "tsk_recover directory: $directory_tsk_recover"
}

# Get evidence file
get_evidence_file() {
    if [[ -z "$evidence_file" ]]; then
        read -p "Evidence file path: " evidence_file
    fi

    if [[ -z "$evidence_file" ]]; then
        log_error "Evidence file path cannot be empty"
        exit 1
    fi

    # Expand path (support for ~)
    evidence_file="${evidence_file/#\~/$HOME}"

    if [[ ! -f "$evidence_file" ]]; then
        log_error "Evidence file does not exist: $evidence_file"
        exit 1
    fi

    if [[ ! -r "$evidence_file" ]]; then
        log_error "Evidence file is not readable: $evidence_file"
        exit 1
    fi

    log_success "Evidence file found: $evidence_file"
    log_info "Calculating MD5 hash of evidence file..."
    
    if md5sum "$evidence_file" >> "$directory_case/md5sum.txt" 2>>"$log_file"; then
        log_success "MD5 hash calculated and saved"
    else
        log_warning "Failed to calculate MD5 hash"
    fi
}

# Display partition layout
display_partition_layout() {
    log_info "Displaying partition layout..."
    echo ""
    echo "=== Partition Layout ==="
    if mmls "$evidence_file" 2>>"$log_file"; then
        echo ""
        log_success "Partition layout displayed"
    else
        log_error "Error displaying partition layout"
        exit 1
    fi
}

# Check if file is encrypted
check_encryption() {
    local offset="$1"
    log_info "Checking encryption at offset $offset..."
    
    local xxd_output
    if ! xxd_output=$(dd if="$evidence_file" bs=1 skip="$offset" count=16 2>/dev/null | xxd -l 16 2>/dev/null); then
        log_error "Cannot read file at specified offset"
        return 1
    fi

    if [[ "$xxd_output" =~ $ENCRYPTED_SIGNATURE ]]; then
        log_error "Evidence file appears to be encrypted (BitLocker detected)"
        return 1
    fi

    log_success "File does not appear to be encrypted"
    return 0
}

# Extract artifacts
extract_artefacts() {
    if [[ -z "$offsetevidence" ]]; then
        read -p "First system partition offset: " offsetevidence
    fi

    if [[ -z "$offsetevidence" ]]; then
        log_error "Offset cannot be empty"
        exit 1
    fi

    if ! [[ "$offsetevidence" =~ ^[[:digit:]]+$ ]]; then
        log_error "Offset must be an integer: $offsetevidence"
        exit 1
    fi

    log_info "Partition offset: $offsetevidence"

    # Check encryption
    if ! check_encryption "$offsetevidence"; then
        exit 1
    fi

    # Extract MFT
    log_info "Extracting MFT (Master File Table)..."
    if icat -o "$offsetevidence" "$evidence_file" 0 > "$directory_icat/MFT" 2>>"$log_file"; then
        log_success "MFT extracted: $directory_icat/MFT"
        if md5sum "$directory_icat/MFT" >> "$directory_icat/md5sum.txt" 2>>"$log_file"; then
            log_info "MFT MD5 hash calculated"
        fi
    else
        log_error "Failed to extract MFT"
        exit 1
    fi

    # Search for artifacts
    log_info "Searching for artifacts in file system..."
    > "$fls_output"  # Reset file
    
    local found_count=0
    for artefact in "${ARTEFACT_ARRAY[@]}"; do
        if fls -r -o "$offsetevidence" "$evidence_file" 2>>"$log_file" | grep -i "$artefact" >> "$fls_output" 2>>"$log_file"; then
            ((found_count++)) || true
        fi
    done

    log_info "$found_count artifact types found"

    if [[ ! -f "$fls_output" ]] || [[ ! -s "$fls_output" ]]; then
        log_warning "No artifacts found or problem with file $fls_output"
        return 0
    fi

    # Extract with icat
    log_info "Extracting artifacts with icat..."
    local extracted_count=0
    local failed_count=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        local artefact_inode artefact_name
        
        artefact_inode=$(echo "$line" | awk '{print $3}' | cut -d ':' -f 1)
        artefact_name=$(echo "$line" | awk '{print $4}')

        if [[ -n "$artefact_inode" ]] && [[ -n "$artefact_name" ]] && [[ $artefact_inode =~ ^[[:digit:]]+-[[:digit:]]+-[[:digit:]]+$ ]]; then
            # Clean filename
            artefact_name=$(echo "$artefact_name" | tr -d '/\\:*?"<>|')
            
            if icat -o "$offsetevidence" "$evidence_file" "$artefact_inode" > "$directory_icat/$artefact_name" 2>>"$log_file"; then
                log_success "File extracted: $artefact_name (inode: $artefact_inode)"
                if md5sum "$directory_icat/$artefact_name" >> "$directory_icat/md5sum.txt" 2>>"$log_file"; then
                    ((extracted_count++)) || true
                else
                    log_warning "Failed to calculate hash for: $artefact_name"
                fi
            else
                log_warning "Failed to extract: $artefact_name"
                ((failed_count++)) || true
            fi
        fi
    done < "$fls_output"

    log_info "Extraction completed: $extracted_count files extracted, $failed_count failures"

    # Extract with tsk_recover
    log_info "Full extraction with tsk_recover..."
    if tsk_recover -a -o "$offsetevidence" "$evidence_file" "$directory_tsk_recover" >>"$log_file" 2>&1; then
        log_success "tsk_recover extraction completed: $directory_tsk_recover"
    else
        log_warning "Issues encountered during tsk_recover extraction (see log)"
    fi
}

# Display summary
show_summary() {
    echo ""
    echo "=== Extraction Summary ==="
    echo "Case directory: $directory_case"
    echo "Evidence file: $evidence_file"
    echo "Offset used: $offsetevidence"
    echo ""
    echo "Files extracted with icat: $directory_icat"
    echo "Files extracted with tsk_recover: $directory_tsk_recover"
    echo "Log file: $log_file"
    echo ""
    
    if [[ -f "$directory_icat/md5sum.txt" ]]; then
        local hash_count
        hash_count=$(wc -l < "$directory_icat/md5sum.txt" | tr -d ' ')
        echo "Number of files with MD5 hash: $hash_count"
    fi
    
    log_info "Extraction completed successfully"
}



parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            -d|--directory)
                directory_case="$2"
                shift 2
                ;;
            -e|--evidence)
                evidence_file="$2"
                shift 2
                ;;
            -o|--offset)
                offsetevidence="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}


main() {
    parse_arguments "$@"
    
    echo "=== $SCRIPT_NAME v$SCRIPT_VERSION ==="
    echo ""
    
    check_requirements
    create_directories
    get_evidence_file
    display_partition_layout
    extract_artefacts
    show_summary
    
    echo ""
    log_success "Script completed successfully"
}

# Execute main script
main "$@"
