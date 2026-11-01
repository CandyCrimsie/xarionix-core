#!/usr/bin/env bash
# Never echo commands, including when called as bash -x install.sh.
set +x
set -euo pipefail
umask 077

printf '%s\n' '========================================' '         Xarionix Core Setup' '========================================' '' 'Select installation language:' 'Выберите язык установки:' '' '  1) Русский' '  2) English' ''

setup_language=''
setup_non_interactive=false
setup_previous=''
for setup_arg in "$@"; do
  if [[ "$setup_arg" == '--non-interactive' ]]; then setup_non_interactive=true; fi
  if [[ "$setup_previous" == '--language' && "$setup_arg" =~ ^(ru|en)$ ]]; then setup_language="$setup_arg"; fi
  setup_previous="$setup_arg"
done
if [[ "$setup_non_interactive" == false ]]; then
  printf '%s' 'Choice / Выбор [1]: '
  IFS= read -r setup_choice || exit 1
  case "$setup_choice" in
    2) setup_language=en ;;
    1|'') setup_language=ru ;;
    *) printf '%s\n' 'Неверный выбор / Invalid choice' >&2; exit 1 ;;
  esac
fi
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' >/dev/null 2>&1; then
  if [[ "$setup_language" == en ]]; then
    printf '%s\n' 'Python 3.12+ is required.' >&2
  else
    printf '%s\n' 'Требуется Python 3.12+.' >&2
  fi
  exit 1
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ -n "$setup_language" ]]; then
  exec python3 -m scripts.setup install "$@" --language "$setup_language"
fi
exec python3 -m scripts.setup install "$@"
