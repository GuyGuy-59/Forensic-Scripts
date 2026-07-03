#!/bin/bash

# Forensic Collector for Windows - Forensic artifact extraction script
# Description: Extracts Windows system artifacts from a disk image

set -euo pipefail

readonly SCRIPT_NAME="Forensic Collector Win"
readonly SCRIPT_VERSION="2.1"
readonly REQUIRED_TOOLS=("mmls" "icat" "fls" "tsk_recover" "xxd" "dd" "md5sum")

# Individual files — matched against full paths produced by fls -r -p
readonly ARTEFACT_FILES=(
    'Windows/System32/config/SYSTEM'        'Windows/System32/config/SECURITY'
    'Windows/System32/config/SAM'           'Windows/System32/config/SOFTWARE'
    'NTUSER.DAT'                            'UsrClass.dat'
    'pagefile.sys'                          'hiberfil.sys'
    'Windows/INF/setupapi.dev.log'          'Windows/System32/drivers/etc/hosts'
)

# Directories collected entirely — full path prefix as produced by fls -r -p
readonly ARTEFACT_DIRS=(
    'Windows/Prefetch'
    'Windows/Tasks'
    'Windows/System32/Tasks'
    'Windows/System32/config/RegBack'
    'Windows/System32/sru'
    'Windows/System32/winevt/Logs'
    'Windows/System32/Logfiles/W3SVC1'
    'Windows/appcompat/Programs'
    '$Recycle.Bin'
)

readonly ENCRYPTED_SIGNATURE="eb58 902d 4656 452d 4653 2d00 0208 0000"

directory_case=""
directory_icat=""
directory_tsk_recover=""
evidence_file=""
offsetevidence=""
fls_output=""
log_file=""
MAX_JOBS=4

log() {
    local level="$1"; shift
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ -n "$log_file" ]]; then
        echo "[$timestamp] [$level] $*" | tee -a "$log_file"
    else
        echo "[$timestamp] [$level] $*"
    fi
}

log_info()    { log "INFO"    "$@"; }
log_error()   { log "ERROR"   "$@" >&2; }
log_warning() { log "WARNING" "$@"; }
log_success() { log "SUCCESS" "$@"; }

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
    -j, --jobs N        Number of parallel icat jobs (default: 4)

Description:
    This script extracts Windows forensic artifacts from a disk image
    using SleuthKit (TSK) tools.

Examples:
    $0
    $0 -d "Case001" -e "/path/to/image.dd" -o 2048
    $0 -d "Case001" -e "/path/to/image.dd" -j 8
EOF
}

check_requirements() {
    log_info "Checking requirements..."
    local missing=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing tools: ${missing[*]}"
        log_error "Please install SleuthKit (TSK) and required system tools."
        exit 1
    fi
    log_success "All requirements are installed"
}

create_directories() {
    if [[ -z "$directory_case" ]]; then
        read -p "Case directory name: " directory_case
    fi
    [[ -z "$directory_case" ]] && { log_error "Case directory name cannot be empty"; exit 1; }

    directory_case=$(echo "$directory_case" | tr -d '/\\:*?"<>|' | tr ' ' '_')
    directory_icat="$directory_case/result_icat"
    directory_tsk_recover="$directory_case/result_tsk_recover"
    log_file="$directory_case/forensic_collector.log"

    mkdir -p "$directory_case" "$directory_icat" "$directory_tsk_recover" 2>/dev/null \
        || { log_error "Cannot create directories: $directory_case"; exit 1; }

    fls_output="$directory_icat/fls_output.txt"
    echo "=== $SCRIPT_NAME v$SCRIPT_VERSION - Session started ===" > "$log_file"
    log_info "Case directory: $directory_case"
    log_info "icat output: $directory_icat"
    log_info "tsk_recover output: $directory_tsk_recover"
}

get_evidence_file() {
    if [[ -z "$evidence_file" ]]; then
        read -p "Evidence file path: " evidence_file
    fi
    [[ -z "$evidence_file" ]] && { log_error "Evidence file path cannot be empty"; exit 1; }

    evidence_file="${evidence_file/#\~/$HOME}"
    [[ ! -f "$evidence_file" ]] && { log_error "File does not exist: $evidence_file"; exit 1; }
    [[ ! -r "$evidence_file" ]] && { log_error "File is not readable: $evidence_file"; exit 1; }

    log_success "Evidence file: $evidence_file"
    log_info "Calculating MD5..."
    #md5sum "$evidence_file" >> "$directory_case/md5sum.txt" 2>>"$log_file" \
    #    && log_success "MD5 hash saved" || log_warning "MD5 calculation failed"
}

convert_to_raw() {
    local format=""
    case "${evidence_file,,}" in
        *.vmdk) format="vmdk" ;; *.vhd)   format="vhd"   ;; *.vhdx) format="vhdx" ;;
        *.vdi)  format="vdi"  ;; *.qcow2) format="qcow2" ;; *.qcow) format="qcow"  ;;
    esac
    if [[ -z "$format" ]]; then
        local magic
        magic=$(file -b "$evidence_file" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        [[ "$magic" =~ vmware ]] && format="vmdk"
    fi
    [[ -z "$format" ]] && { log_info "Raw format detected — no conversion needed"; return 0; }

    log_info "Non-raw format: $format — converting..."
    local raw="${evidence_file%.*}.raw"

    if [[ -f "$raw" ]]; then
        log_info "Raw image already exists: $raw"
        evidence_file="$raw"; return 0
    fi

    if command -v qemu-img &>/dev/null; then
        local vsize avail
        vsize=$(qemu-img info "$evidence_file" 2>/dev/null \
            | grep "virtual size" | grep -oE '\([0-9]+ bytes\)' | grep -oE '[0-9]+')
        avail=$(df --output=avail -B1 "$(dirname "$raw")" 2>/dev/null | tail -1 | tr -d ' ')
        if [[ -n "$vsize" && -n "$avail" ]] && (( vsize > avail )); then
            log_error "Insufficient disk space (need ${vsize}B, have ${avail}B)"
            exit 1
        fi
    fi

    command -v qemu-nbd &>/dev/null || { log_error "qemu-nbd not found (install qemu-utils)"; exit 1; }
    modprobe nbd max_part=8 2>/dev/null || true

    local nbd_dev=""
    for i in $(seq 0 15); do
        [[ -b "/dev/nbd${i}" && ! -f "/sys/class/block/nbd${i}/pid" ]] \
            && { nbd_dev="/dev/nbd${i}"; break; }
    done
    [[ -z "$nbd_dev" ]] && { log_error "No free nbd device found"; exit 1; }

    log_info "Attaching to $nbd_dev..."
    qemu-nbd -r -c "$nbd_dev" "$evidence_file" 2>>"$log_file" \
        || { log_error "Failed to attach image"; exit 1; }

    log_info "Converting with dd (may take a while)..."
    local rc=0
    dd if="$nbd_dev" of="$raw" bs=4M status=progress 2>>"$log_file" || rc=$?
    qemu-nbd -d "$nbd_dev" 2>>"$log_file"

    if [[ $rc -ne 0 ]]; then
        log_error "dd conversion failed"; rm -f "$raw"; exit 1
    fi

    log_success "Conversion done: $raw"
    evidence_file="$raw"
    #md5sum "$evidence_file" >> "$directory_case/md5sum.txt" 2>>"$log_file" || true
}

# Display mmls output and set offsetevidence interactively if not provided via CLI
get_partition_offset() {
    log_info "Reading partition layout..."
    echo ""
    echo "=== Partition Layout (mmls) ==="

    local mmls_out
    mmls_out=$(mmls "$evidence_file" 2>>"$log_file") || { log_error "mmls failed"; exit 1; }
    echo "$mmls_out"
    echo ""

    if [[ -n "$offsetevidence" ]]; then
        log_info "Using provided offset: $offsetevidence"
        return 0
    fi

    # Parse only real partition lines (slot format NNN:MMM, not Meta/Unallocated)
    local -a offsets=() labels=()
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*[0-9]+:[[:space:]]+[0-9]+:[0-9]+ ]]; then
            local start desc
            start=$(echo "$line" | awk '{print $3}' | sed 's/^0*//')
            [[ -z "$start" ]] && start="0"
            desc=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}' | sed 's/[[:space:]]*$//')
            offsets+=("$start")
            labels+=("offset=$start  $desc")
        fi
    done <<< "$mmls_out"

    if [[ ${#offsets[@]} -eq 0 ]]; then
        log_warning "No parseable partitions found in mmls output"
        _ask_manual_offset
        return 0
    fi

    echo "Select the Windows system partition:"
    local i
    for i in "${!labels[@]}"; do
        printf "  %d.  %s\n" "$((i+1))" "${labels[$i]}"
    done
    printf "  m.  Enter offset manually\n\n"

    local sel
    while true; do
        read -p "Choice [1-${#offsets[@]}/m]: " sel
        case "$sel" in
            m|M) _ask_manual_offset; break ;;
            *)
                if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#offsets[@]} )); then
                    offsetevidence="${offsets[$((sel-1))]}"
                    log_info "Partition $sel selected — offset: $offsetevidence"
                    break
                fi
                log_warning "Invalid choice, please try again"
                ;;
        esac
    done
}

_ask_manual_offset() {
    local input
    while true; do
        read -p "Enter offset (sectors): " input
        if [[ "$input" =~ ^[0-9]+$ ]]; then
            offsetevidence="$input"
            log_info "Manual offset: $offsetevidence"
            break
        fi
        log_warning "Offset must be a positive integer"
    done
}

check_encryption() {
    local offset="$1"
    log_info "Checking for BitLocker encryption at offset $offset..."
    local hex
    hex=$(dd if="$evidence_file" bs=512 skip="$offset" count=1 2>/dev/null | xxd -l 16 2>/dev/null) \
        || { log_error "Cannot read at offset $offset"; return 1; }
    if [[ "$hex" =~ $ENCRYPTED_SIGNATURE ]]; then
        log_error "BitLocker encryption detected — cannot extract artifacts"
        return 1
    fi
    log_success "No encryption detected"
}

extract_from_line() {
    local fls_line="$1"
    [[ "${fls_line:0:3}" == "d/d" ]] && return 0

    local inode full_path
    inode=$(echo "$fls_line" | awk '{print $2}' | cut -d ':' -f 1)
    full_path=$(echo "$fls_line" | sed 's/^[^:]*:[[:space:]]*//')

    [[ ! "$inode" =~ ^[0-9]+-[0-9]+-[0-9]+$ ]] && return 0
    [[ -z "$full_path" ]] && return 0

    local dest="$directory_icat/$full_path"
    mkdir -p "$(dirname "$dest")" 2>/dev/null

    if icat -o "$offsetevidence" "$evidence_file" "$inode" > "$dest" 2>>"$log_file"; then
        log_success "Extracted: $full_path (inode $inode)"
        md5sum "$dest" >> "$directory_icat/md5sum.txt" 2>>"$log_file" || true
    else
        log_warning "Failed: $full_path"
        rm -f "$dest"
        return 1
    fi
}

# Run extract_from_line for each line in a file, MAX_JOBS in parallel.
# Prints "ok fail" counts to stdout when done.
_parallel_extract() {
    local lines_file="$1"
    local status_dir
    status_dir=$(mktemp -d)
    local -a batch_pids=()

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        (
            # Redirect stdout to stderr so log messages (via tee) don't pollute
            # the "ok fail" count returned via command substitution.
            exec 1>&2
            if extract_from_line "$line"; then
                touch "${status_dir}/ok_${BASHPID}"
            else
                touch "${status_dir}/fail_${BASHPID}"
            fi
        ) &
        batch_pids+=($!)

        if (( ${#batch_pids[@]} >= MAX_JOBS )); then
            for p in "${batch_pids[@]}"; do wait "$p" 2>/dev/null || true; done
            batch_pids=()
        fi
    done < "$lines_file"

    if [[ ${#batch_pids[@]} -gt 0 ]]; then
        for p in "${batch_pids[@]}"; do wait "$p" 2>/dev/null || true; done
    fi

    local ok fail
    ok=$(find "$status_dir" -maxdepth 1 -name 'ok_*' | wc -l)
    fail=$(find "$status_dir" -maxdepth 1 -name 'fail_*' | wc -l)
    rm -rf "$status_dir"
    echo "$ok $fail"
}

extract_artefacts() {
    [[ ! "$offsetevidence" =~ ^[[:digit:]]+$ ]] \
        && { log_error "Offset must be an integer: $offsetevidence"; exit 1; }

    log_info "Partition offset: $offsetevidence — parallel jobs: $MAX_JOBS"
    check_encryption "$offsetevidence" || exit 1

    # NTFS metadata files by fixed inode
    log_info 'Extracting $MFT and $LogFile...'
    for meta in "0:MFT" "2:LogFile"; do
        local meta_inode="${meta%%:*}" meta_name="${meta##*:}"
        if icat -o "$offsetevidence" "$evidence_file" "$meta_inode" \
                > "$directory_icat/$meta_name" 2>>"$log_file"; then
            log_success "$meta_name extracted (inode $meta_inode)"
            md5sum "$directory_icat/$meta_name" >> "$directory_icat/md5sum.txt" 2>>"$log_file" || true
        else
            [[ "$meta_inode" == "0" ]] && { log_error "Failed to extract MFT"; exit 1; }
            log_warning "Failed to extract $meta_name"
        fi
    done

    # Full filesystem listing with full paths (-p), run once and cache
    local fls_full="$directory_icat/fls_full.txt"
    log_info "Building filesystem listing (fls -r -p)..."
    fls -r -p -o "$offsetevidence" "$evidence_file" > "$fls_full" 2>>"$log_file" || true
    [[ ! -s "$fls_full" ]] && { log_error "fls listing is empty — cannot extract artifacts"; exit 1; }
    log_success "$(wc -l < "$fls_full") filesystem entries"

    # tsk_recover runs in background while icat extractions proceed
    local tsk_log="$directory_case/tsk_recover.log"
    log_info "Starting tsk_recover in background..."
    tsk_recover -o "$offsetevidence" "$evidence_file" "$directory_tsk_recover" \
        >"$tsk_log" 2>&1 &
    local tsk_pid=$!

    local total_ok=0 total_fail=0

    # Individual targeted files
    log_info "Extracting individual artifacts (jobs=$MAX_JOBS)..."
    local tmp_lines
    tmp_lines=$(mktemp)
    for artefact in "${ARTEFACT_FILES[@]}"; do
        grep -i "$artefact" "$fls_full" || true
    done > "$tmp_lines"

    if [[ -s "$tmp_lines" ]]; then
        local counts
        counts=$(_parallel_extract "$tmp_lines")
        total_ok=$(( total_ok + ${counts%% *} ))
        total_fail=$(( total_fail + ${counts##* } ))
    fi
    rm -f "$tmp_lines"

    # Full directory collections
    log_info "Extracting directory artifacts (jobs=$MAX_JOBS)..."
    local artefact_dir
    for artefact_dir in "${ARTEFACT_DIRS[@]}"; do
        local dir_lines
        dir_lines=$(mktemp)
        grep -i "${artefact_dir}/" "$fls_full" > "$dir_lines" 2>/dev/null || true

        if [[ ! -s "$dir_lines" ]]; then
            log_warning "Not found: $artefact_dir"
            rm -f "$dir_lines"; continue
        fi

        log_info "Collecting: $artefact_dir ($(wc -l < "$dir_lines") entries)"
        local counts
        counts=$(_parallel_extract "$dir_lines")
        local ok=${counts%% *} fail=${counts##* }
        total_ok=$(( total_ok + ok ))
        total_fail=$(( total_fail + fail ))
        log_info "  -> $ok files extracted from $artefact_dir"
        rm -f "$dir_lines"
    done

    log_info "icat extraction: $total_ok files extracted, $total_fail failures"

    # Wait for background tsk_recover
    log_info "Waiting for tsk_recover to finish..."
    if wait "$tsk_pid"; then
        log_success "tsk_recover completed: $directory_tsk_recover"
    else
        log_warning "tsk_recover had issues (see $tsk_log)"
    fi
}

show_summary() {
    echo ""
    echo "=== Extraction Summary ==="
    echo "Case directory : $directory_case"
    echo "Evidence file  : $evidence_file"
    echo "Offset         : $offsetevidence"
    echo "icat results   : $directory_icat"
    echo "tsk_recover    : $directory_tsk_recover"
    echo "Log            : $log_file"
    if [[ -f "$directory_icat/md5sum.txt" ]]; then
        echo "MD5 entries    : $(wc -l < "$directory_icat/md5sum.txt" | tr -d ' ')"
    fi
    echo ""
    log_info "Extraction completed successfully"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)      show_help; exit 0 ;;
            -v|--version)   echo "$SCRIPT_NAME v$SCRIPT_VERSION"; exit 0 ;;
            -d|--directory) directory_case="$2"; shift 2 ;;
            -e|--evidence)  evidence_file="$2"; shift 2 ;;
            -o|--offset)    offsetevidence="$2"; shift 2 ;;
            -j|--jobs)      MAX_JOBS="$2"; shift 2 ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
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
    get_partition_offset
    extract_artefacts
    show_summary
    echo ""
    log_success "Script completed successfully"
}

main "$@"
