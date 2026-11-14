"""Retain all command evidence while excluding build trees and private homes."""
from pathlib import Path
import os
import shutil
import sys

root=Path(sys.argv[1]);destination=Path(sys.argv[2]);destination.mkdir(exist_ok=True)
for directory,children,files in os.walk(root):
    children[:]=[name for name in children if name!='home' and name!='images'
                 and not name.startswith(('target-','source-'))]
    for name in files:
        source=Path(directory)/name
        if source.suffix in ('.json','.log','.stdout','.stderr'):
            target=destination/source.relative_to(root);target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
