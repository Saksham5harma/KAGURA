import os
import time


# -----------------------------------
# TERMINAL COLORS
# -----------------------------------
RED = "\033[91m"
GOLD = "\033[93m"
WHITE = "\033[97m"
CYAN = "\033[96m"
RESET = "\033[0m"


# -----------------------------------
# CLEAR TERMINAL
# -----------------------------------
def clear_screen():
    os.system("clear")


# -----------------------------------
# TYPEWRITER EFFECT
# -----------------------------------
def slow_print(text, delay=0.0015):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


# -----------------------------------
# MAIN BANNER
# -----------------------------------
def show_banner():

    clear_screen()

    banner = f"""
{RED}
██╗  ██╗ █████╗  ██████╗ ██╗   ██╗██████╗  █████╗
██║ ██╔╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗
█████╔╝ ███████║██║  ███╗██║   ██║██████╔╝███████║
██╔═██╗ ██╔══██║██║   ██║██║   ██║██╔══██╗██╔══██║
██║  ██╗██║  ██║╚██████╔╝╚██████╔╝██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
{RESET}

{RED}                 神楽 KAGURA{RESET}

{GOLD}              FOR RED TEAMERS{RESET}

{CYAN}      Offensive Security Intelligence Framework{RESET}

────────────────────────────────────────────────────────────
"""

    slow_print(banner, delay=0.0008)

    # -----------------------------------
    # LOADING ANIMATION
    # -----------------------------------
    modules = [
        "Loading Recon Engine",
        "Loading Port Scanner",
        "Loading Vulnerability Engine",
        "Loading Threat Intelligence",
        "Initializing Report System"
    ]

    for module in modules:
        print(f"{WHITE}[+] {module}...{RESET}")
        time.sleep(0.2)

    print(f"\n{GOLD}[✓] KAGURA READY{RESET}\n")
