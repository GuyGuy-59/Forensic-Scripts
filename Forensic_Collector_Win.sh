#!/bin/bash


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