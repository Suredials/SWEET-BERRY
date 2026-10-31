#!/bin/sh
set -eu
# Per-process address space bound, inherited by child processes and not raisable
# without CAP_SYS_RESOURCE. PID and CPU limits complement this kernel's missing MEMCG.
ulimit -v 131072
ulimit -f 10240
exec php -d opcache.enable=0 -d opcache.enable_cli=0 -d opcache.jit=0 -d opcache.jit_buffer_size=0 -d auto_prepend_file=/opt/trace.php -d user_ini.filename= -d upload_max_filesize=5M -d post_max_size=6M -d display_errors=0 -S 0.0.0.0:8080 -t /srv/app
