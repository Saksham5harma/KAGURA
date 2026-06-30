import os
import time
import sys
import random

RED     = "\033[91m"
DRED    = "\033[31m"
GOLD    = "\033[93m"
WHITE   = "\033[97m"
CYAN    = "\033[96m"
DCYAN   = "\033[36m"
GREEN   = "\033[92m"
MAGENTA = "\033[95m"
GRAY    = "\033[90m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

def clear_screen():
    os.system("clear")

def slow_print(text, delay=0.0015):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

GLITCH_CHARS = "!@#$%^&*<>?/\\|~`░▒▓█"

def glitch_line(text, intensity=2):
    chars = list(text)
    for _ in range(intensity):
        idx = random.randint(0, len(chars) - 1)
        if chars[idx] not in (' ', '\n'):
            chars[idx] = random.choice(GLITCH_CHARS)
    return "".join(chars)

def glitch_print(lines, rounds=3, delay=0.04):
    for _ in range(rounds):
        sys.stdout.write("\033[{}A".format(len(lines)))
        for line in lines:
            print(f"{RED}{glitch_line(line)}{RESET}")
        time.sleep(delay)
    # Final clean render
    sys.stdout.write("\033[{}A".format(len(lines)))
    for line in lines:
        print(f"{RED}{BOLD}{line}{RESET}")

def scanline_loader(label, width=44):
    bar_chars = ["░", "▒", "▓", "█"]
    sys.stdout.write(f"  {CYAN}{label:<28}{RESET} {GRAY}[{RESET}")
    sys.stdout.flush()
    for i in range(width):
        char = bar_chars[min(i // (width // 4), 3)]
        color = CYAN if i < width * 0.6 else (GOLD if i < width * 0.85 else GREEN)
        sys.stdout.write(f"{color}{char}{RESET}")
        sys.stdout.flush()
        time.sleep(0.018)
    sys.stdout.write(f"{GRAY}]{RESET} {GREEN}✓{RESET}\n")
    sys.stdout.flush()

def pulse_sep(char="─", length=62, color=RED):
    line = char * length
    print(f"{color}{line}{RESET}")

KAGURA_LINES = [
    r"  ██╗  ██╗ █████╗  ██████╗ ██╗   ██╗██████╗  █████╗  ",
    r"  ██║ ██╔╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗ ",
    r"  █████╔╝ ███████║██║  ███╗██║   ██║██████╔╝███████║ ",
    r"  ██╔═██╗ ██╔══██║██║   ██║██║   ██║██╔══██╗██╔══██║ ",
    r"  ██║  ██╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║ ",
    r"  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ",
]

def show_banner():
    clear_screen()

    print()
    print(f"  {GRAY}{'▄' * 60}{RESET}")
    print()

    for line in KAGURA_LINES:
        print(f"{RED}{BOLD}{line}{RESET}")
    time.sleep(0.15)
    glitch_print(KAGURA_LINES, rounds=4, delay=0.05)

    print()
    print(f"  {RED}{'═' * 8}  {BOLD}神楽  KAGURA{RESET}{RED}  {'═' * 8}{RESET}")
    time.sleep(0.08)
    print(f"  {GOLD}{BOLD}       FOR RED TEAMERS — STRIKE UNSEEN{RESET}")
    time.sleep(0.05)
    print(f"  {DCYAN}    Offensive Security Intelligence Framework{RESET}")
    print()

    pulse_sep("─", 62, DRED)
    print()

    modules = [
        ("Recon Engine",          "v2.4.1"),
        ("Port Scanner",          "v1.9.0"),
        ("Vulnerability Engine",  "v3.1.2"),
        ("Threat Intelligence",   "v2.0.7"),
        ("Exploit Suggester",     "v1.5.3"),
        ("Report System",         "v1.2.0"),
    ]

    print(f"  {GRAY}Initializing subsystems...{RESET}\n")
    for name, ver in modules:
        label = f"{name} {GRAY}{ver}{RESET}"
        scanline_loader(label, width=30)
        time.sleep(0.05)

    print()
    pulse_sep("─", 62, DRED)
    print()
    print(f"  {GREEN}{BOLD}[✓] ALL SYSTEMS ONLINE{RESET}   "
          f"{GRAY}|{RESET}   "
          f"{GOLD}SESSION ENCRYPTED{RESET}   "
          f"{GRAY}|{RESET}   "
          f"{RED}STEALTH MODE: ACTIVE{RESET}")
    print()
    print(f"  {GRAY}{'▀' * 60}{RESET}")
    print()

    for _ in range(2):
        sys.stdout.write(f"  {RED}▶ {GOLD}kagura ~/{RESET}  \r")
        sys.stdout.flush()
        time.sleep(0.35)
        sys.stdout.write(f"  {RED}  {GOLD}kagura ~/{RESET}  \r")
        sys.stdout.flush()
        time.sleep(0.35)
    print(f"  {RED}▶ {GOLD}kagura ~/{RESET} ", end="", flush=True)
    print()

if __name__ == "__main__":
    show_banner()
