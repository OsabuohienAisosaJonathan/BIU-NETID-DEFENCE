import os
import glob

def replace_in_files():
    templates_path = r"c:\xampp\htdocs\Anom\templates\*.html"
    files = glob.glob(templates_path)
    
    replacements = {
        'text-muted': 'text-black',
        'text-secondary': 'text-black',
        '#6c757d': '#000000',
        '#4a5568': '#000000',
        '#cbd5e1': '#000000',
        '#a3b8cc': '#000000'
    }
    
    for file in files:
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        modified = False
        for old, new in replacements.items():
            if old in content:
                content = content.replace(old, new)
                modified = True
                
        if modified:
            with open(file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated {file}")

if __name__ == "__main__":
    replace_in_files()
