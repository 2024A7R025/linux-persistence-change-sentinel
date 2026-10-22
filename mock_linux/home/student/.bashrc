# ~/.bashrc: sample student user shell startup (Mock Environment - Safe Demo)
case $- in
    *i*) ;;
      *) return;;
esac

# Standard user aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
