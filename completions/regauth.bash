# bash completion for regauth
# Install: make install-completion   (or copy to /etc/bash_completion.d/regauth)

_regauth() {
    local cur prev cmd sub
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    cmd=""
    sub=""
    local i
    for ((i = 1; i < COMP_CWORD; i++)); do
        if [[ "${COMP_WORDS[i]}" != -* ]]; then
            if [[ -z "$cmd" ]]; then
                cmd="${COMP_WORDS[i]}"
            elif [[ -z "$sub" ]]; then
                sub="${COMP_WORDS[i]}"
            fi
        fi
    done

    case "$prev" in
        -c)
            _filedir yaml 2>/dev/null || COMPREPLY=( $(compgen -f -X '!*.yaml' -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        case "$cmd:$sub" in
            server:)   COMPREPLY=( $(compgen -W "-c -insecure -h" -- "$cur") ) ;;
            keystore:*) COMPREPLY=( $(compgen -W "-c -h" -- "$cur") ) ;;
            *)         COMPREPLY=( $(compgen -W "-h" -- "$cur") ) ;;
        esac
        return 0
    fi

    if [[ -z "$cmd" ]]; then
        COMPREPLY=( $(compgen -W "server keystore -h" -- "$cur") )
        return 0
    fi

    if [[ "$cmd" == "keystore" && -z "$sub" ]]; then
        COMPREPLY=( $(compgen -W "list rotate rotate-v2 revoke delete cleanup -h" -- "$cur") )
        return 0
    fi

    return 0
}

complete -F _regauth regauth
