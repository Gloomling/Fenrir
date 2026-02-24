# fenrir/cli.py
import argparse
import asyncio
from .logging_config import log
from .fenrir_gui import launch_gui
# Import all scanner modules
from .modules import *

async def run_scans(args):
    """Orchestrates the execution of different scan modules based on arguments."""
    target = args.target
    # ... (all the previous CLI logic remains here) ...

def main():
    """Main entry point for the Fenrir CLI."""
    parser = argparse.ArgumentParser(description="Fenrir Security Scanner", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--gui", action="store_true", help="Launch the graphical user interface.")
    # ... (all the previous argument definitions remain here) ...
    
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return
        
    # ... (all the previous CLI execution logic remains here) ...

if __name__ == "__main__":
    main()
