import re

with open('frontend/src/index.css', 'r') as f:
    css = f.read()

# Replace variables
css = css.replace('--bg-deep:        #050912;', '--bg-deep:        #f1f5f9;')
css = css.replace('--bg-dark:        #080e1c;', '--bg-dark:        #e2e8f0;')
css = css.replace('--bg-panel:       rgba(13, 20, 40, 0.85);', '--bg-panel:       rgba(255, 255, 255, 0.85);')
css = css.replace('--bg-card:        rgba(16, 24, 48, 0.70);', '--bg-card:        rgba(255, 255, 255, 0.90);')
css = css.replace('--bg-input:       rgba(10, 16, 34, 0.90);', '--bg-input:       #ffffff;')
css = css.replace('--bg-hover:       rgba(30, 48, 90, 0.50);', '--bg-hover:       rgba(0, 0, 0, 0.05);')

css = css.replace('--accent-cyan:    #00e5ff;', '--accent-cyan:    #0ea5e9;')
css = css.replace('--accent-green:   #00ff9d;', '--accent-green:   #10b981;')
css = css.replace('--accent-purple:  #a855f7;', '--accent-purple:  #8b5cf6;')
css = css.replace('--accent-amber:   #fbbf24;', '--accent-amber:   #d97706;')
css = css.replace('--accent-red:     #ff4d6d;', '--accent-red:     #e11d48;')

css = css.replace('--col-allow:      #00ff9d;', '--col-allow:      #10b981;')
css = css.replace('--col-sanitize:   #fbbf24;', '--col-sanitize:   #d97706;')
css = css.replace('--col-quarantine: #f97316;', '--col-quarantine: #c2410c;')
css = css.replace('--col-block:      #ff4d6d;', '--col-block:      #e11d48;')

css = css.replace('--col-low:        #00ff9d;', '--col-low:        #10b981;')
css = css.replace('--col-moderate:   #fbbf24;', '--col-moderate:   #d97706;')
css = css.replace('--col-high:       #f97316;', '--col-high:       #c2410c;')
css = css.replace('--col-very-high:  #ff4d6d;', '--col-very-high:  #e11d48;')
css = css.replace('--col-critical:   #e11d48;', '--col-critical:   #be123c;')

css = css.replace('--text-primary:   #e2e8f0;', '--text-primary:   #0f172a;')
css = css.replace('--text-secondary: #94a3b8;', '--text-secondary: #334155;')
css = css.replace('--text-muted:     #4b5e80;', '--text-muted:     #64748b;')
css = css.replace('--text-accent:    #00e5ff;', '--text-accent:    #0ea5e9;')

css = css.replace('--border:         rgba(0, 229, 255, 0.10);', '--border:         rgba(0, 0, 0, 0.10);')
css = css.replace('--border-bright:  rgba(0, 229, 255, 0.30);', '--border-bright:  rgba(0, 0, 0, 0.20);')
css = css.replace('--glass-bg:       rgba(13, 20, 40, 0.60);', '--glass-bg:       rgba(255, 255, 255, 0.60);')

css = css.replace('rgba(0, 229, 255', 'rgba(14, 165, 233')
css = css.replace('rgba(0,229,255', 'rgba(14,165,233')
css = css.replace('rgba(168, 85, 247', 'rgba(139, 92, 246')
css = css.replace('rgba(0,255,157', 'rgba(16,185,129')
css = css.replace('rgba(251,191,36', 'rgba(217,119,6')
css = css.replace('rgba(249,115,22', 'rgba(194,65,12')
css = css.replace('rgba(255,77,109', 'rgba(225,29,72')
css = css.replace('rgba(225,29,72', 'rgba(190,18,60')

css = css.replace('rgba(8, 14, 28, 0.80)', 'rgba(255, 255, 255, 0.80)')
css = css.replace('rgba(255,255,255,0.06)', 'rgba(0,0,0,0.06)')
css = css.replace('rgba(255,255,255,0.05)', 'rgba(0,0,0,0.05)')
css = css.replace('rgba(255,255,255,0.04)', 'rgba(0,0,0,0.04)')
css = css.replace('rgba(255,255,255,0.03)', 'rgba(0,0,0,0.03)')
css = css.replace('rgba(255,255,255,0.1)', 'rgba(0,0,0,0.1)')
css = css.replace('rgba(255,255,255,0.15)', 'rgba(0,0,0,0.15)')
css = css.replace('rgba(255,255,255,0.2)', 'rgba(0,0,0,0.2)')
css = css.replace('rgba(0,0,0,0.20)', 'rgba(0,0,0,0.05)')
css = css.replace('rgba(0,0,0,0.30)', 'rgba(0,0,0,0.08)')
css = css.replace('rgba(0, 0, 0, 0.40)', 'rgba(0,0,0,0.03)')
css = css.replace('rgba(5,9,18,0.95)', 'rgba(255,255,255,0.95)')
css = css.replace('rgba(255,255,255,0.02)', 'rgba(0,0,0,0.02)')
css = css.replace('rgba(255,255,255,0.08)', 'rgba(0,0,0,0.08)')

css = css.replace('color: #020810;', 'color: #ffffff;')

with open('frontend/src/index.css', 'w') as f:
    f.write(css)

print("index.css updated.")
