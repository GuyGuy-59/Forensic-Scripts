#!/bin/bash

# Requirements
check_requirements() {
    local requirements_array=("mmls" "icat" "fls")
    local missing_requirements=()

    for requirement in "${requirements_array[@]}"; do
        if ! command -v "$requirement" &> /dev/null; then
            missing_requirements+=("$requirement")
        fi
    done
    if [[ ${#missing_requirements[@]} -gt 0 ]]; then
        echo "The following requirements are not installed: ${missing_requirements[*]}"
        exit 1
    fi
}


create_directories() {
    read -p "Name for directory case: " directory_case
    directory_icat="$directory_case/result_icat"
    directory_tsk_recover="$directory_case/result_tsk_recover"
    mkdir -p "$directory_case" "$directory_icat" "$directory_tsk_recover"
    fls_output="$directory_icat/fls_output.txt"
}


get_evidence_file() {
    read -p "Path your evidence file: " evidence_file
    if [ -f "$evidence_file" ]; then
        echo "$evidence_file exists"
        md5sum "$evidence_file" >> "$directory_case/md5sum.txt"
    else
        echo "$evidence_file not exists"
        exit
    fi
}


display_partition_layout() {
    mmls "$evidence_file"
}

# Extract artefacts
extract_artefacts() {
    read -p "First offset partition system: " offsetevidence
    if [[ "$offsetevidence" =~ ^[[:digit:]]+$ ]]; then
        #Check if evidence_file is encrypted
        xxd_output=$(dd if="$evidence_file" skip="$offsetevidence" count=1 | xxd -l 16)
        if ! [[  "$xxd_output" =~ "eb58 902d 4656 452d 4653 2d00 0208 0000" ]]; then
        # Get MFT Artefact
        icat -o "$offsetevidence" "$evidence_file" 0 > "$directory_icat/MFT"
        # Get other Artefacts
            for artefact in "${artefact_array[@]}"; do
                fls -r -o "$offsetevidence" "$evidence_file" | grep "$artefact" >> "$fls_output"
            done
            if [ -f "$fls_output" ]; then
                echo "Extract with icat"
                while IFS= read -r line; do
                    artefact_inode=$(echo "$line" | awk '{print $3}' | cut -d ':' -f 1)
                    artefact_name=$(echo "$line" | awk '{print $4}')

                    if [ -n "$artefact_inode" ] && [ -n "$artefact_name" ] && [[ $artefact_inode =~ ^[[:digit:]]+-[[:digit:]]+-[[:digit:]]$ ]]; then
                        icat -o "$offsetevidence" "$evidence_file" "$artefact_inode" > "$directory_icat/$artefact_name"
                        echo "Fichier extrait : $artefact_name"
                        md5sum "$directory_icat/$artefact_name" >> "$directory_icat/md5sum.txt"
                    fi
                done < "$fls_output"
                echo "Extract with tsk_recover"
                tsk_recover -a -o "$offsetevidence" "$evidence_file" "$directory_tsk_recover"
            else
                echo "Problem file $fls_output"
            fi
        else
            echo "$evidence_file is encrypted"
            exit
        fi
    else
        echo "Problem offset $offsetevidence"
    fi
}

artefact_array=("SYSTEM" "SECURITY" "SAM" "SOTWARE" "NTUSER.DAT" "pagefile.sys" "Setup.evtx" "System.evtx" "Security.evtx" "Parameters.evtx" "Application.evtx")

# Main script
check_requirements
create_directories
get_evidence_file
display_partition_layout
extract_artefacts