# bash completion for reguser
# Install: make install-completion   (or copy to /etc/bash_completion.d/reguser)

_reguser() {
    local cur prev cmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    cmd=""
    local i
    for ((i = 1; i < COMP_CWORD; i++)); do
        if [[ "${COMP_WORDS[i]}" != -* ]]; then
            cmd="${COMP_WORDS[i]}"
            break
        fi
    done

    case "$prev" in
        -c)
            _filedir yaml 2>/dev/null || COMPREPLY=( $(compgen -f -X '!*.yaml' -- "$cur") )
            return 0
            ;;
        -p)
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        case "$cmd" in
            clean) COMPREPLY=( $(compgen -W "-c -f -h" -- "$cur") ) ;;
            list) COMPREPLY=( $(compgen -W "-c -all -count -h" -- "$cur") ) ;;
            lock) COMPREPLY=( $(compgen -W "-c -lock -unlock -h" -- "$cur") ) ;;
            hash) COMPREPLY=( $(compgen -W "-p -h" -- "$cur") ) ;;
            add|edit) COMPREPLY=( $(compgen -W "-c -p -h" -- "$cur") ) ;;
            del) COMPREPLY=( $(compgen -W "-c -h" -- "$cur") ) ;;
            *) COMPREPLY=( $(compgen -W "-c -p -f -all -count -lock -unlock -h" -- "$cur") ) ;;
        esac
        return 0
    fi

    if [[ -z "$cmd" ]]; then
        COMPREPLY=( $(compgen -W "list add edit del lock clean hash -h" -- "$cur") )
        return 0
    fi

    return 0
}

complete -F _reguser reguser
