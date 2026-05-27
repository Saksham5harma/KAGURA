export QT_QPA_PLATFORM=xcb
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export LANGUAGE=C.UTF-8

export QT_XKB_CONFIG_ROOT=/usr/share/X11/xkb

cd "$(dirname "$0")"

python3 kagura_gui.py
