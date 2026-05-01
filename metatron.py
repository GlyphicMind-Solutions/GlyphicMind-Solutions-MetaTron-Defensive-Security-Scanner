# ./MetaTron/engine/metatron.py
# MetaTron Security Tool - Launcher
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.



#system imports
import sys
from pathlib import Path
from PyQt5.QtWidgets import QApplication
from gui.metatron_window import MetatronWindow



# ------------------
# Main
# ------------------
def main():
    app = QApplication(sys.argv)
    mind_root = Path(__file__).resolve().parent  # or your shared mind root
    window = MetatronWindow(mind_root=mind_root)
    window.show()
    sys.exit(app.exec_())

# ---------------------------
# if name - main for window
# ---------------------------
if __name__ == "__main__":
    main()

