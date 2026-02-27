# ============================================================
#  background.py — Animated SVG Background Generator
#  Call create_background(static_dir) once at app startup.
# ============================================================

import os

_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%"   stop-color="#0A0A0C">
        <animate attributeName="stop-color"
          values="#0A0A0C;#1a1a2e;#16213e;#0f0f1f;#0A0A0C" dur="20s" repeatCount="indefinite"/>
      </stop>
      <stop offset="30%"  stop-color="#1a1a2e">
        <animate attributeName="stop-color"
          values="#1a1a2e;#16213e;#0f0f1f;#0A0A0C;#1a1a2e" dur="20s" repeatCount="indefinite"/>
      </stop>
      <stop offset="60%"  stop-color="#16213e">
        <animate attributeName="stop-color"
          values="#16213e;#0f0f1f;#0A0A0C;#1a1a2e;#16213e" dur="20s" repeatCount="indefinite"/>
      </stop>
      <stop offset="100%" stop-color="#0f0f1f">
        <animate attributeName="stop-color"
          values="#0f0f1f;#0A0A0C;#1a1a2e;#16213e;#0f0f1f" dur="20s" repeatCount="indefinite"/>
      </stop>
    </linearGradient>
    <radialGradient id="glow1" cx="20%" cy="30%" r="40%">
      <stop offset="0%"  stop-color="#8B5CF6" stop-opacity="0.4"/>
      <stop offset="70%" stop-color="#8B5CF6" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="glow2" cx="80%" cy="70%" r="45%">
      <stop offset="0%"  stop-color="#06b6d4" stop-opacity="0.4"/>
      <stop offset="70%" stop-color="#06b6d4" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="glow3" cx="50%" cy="50%" r="50%">
      <stop offset="0%"  stop-color="#f43f5e" stop-opacity="0.2"/>
      <stop offset="70%" stop-color="#f43f5e" stop-opacity="0"/>
    </radialGradient>
    <pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse">
      <path d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(139,92,246,0.15)" stroke-width="1.5">
        <animate attributeName="stroke"
          values="rgba(139,92,246,0.15);rgba(6,182,212,0.15);rgba(244,63,94,0.15);rgba(139,92,246,0.15)"
          dur="10s" repeatCount="indefinite"/>
      </path>
    </pattern>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  <rect width="100%" height="100%" fill="url(#grad)"/>
  <rect width="100%" height="100%" fill="url(#grid)"/>
  <circle cx="20%" cy="30%" r="300" fill="url(#glow1)" filter="url(#glow)">
    <animate attributeName="r" values="300;320;300" dur="8s"  repeatCount="indefinite"/>
  </circle>
  <circle cx="80%" cy="70%" r="350" fill="url(#glow2)" filter="url(#glow)">
    <animate attributeName="r" values="350;380;350" dur="10s" repeatCount="indefinite"/>
  </circle>
  <circle cx="50%" cy="50%" r="400" fill="url(#glow3)" filter="url(#glow)">
    <animate attributeName="r" values="400;420;400" dur="12s" repeatCount="indefinite"/>
  </circle>
</svg>
"""

BACKGROUND_FILENAME = "premium-bg.svg"
BACKGROUND_URL = f"/static/{BACKGROUND_FILENAME}"


def create_background(static_dir: str) -> str:
    """
    Write the animated SVG background to `static_dir`.
    Returns the URL path to the file (e.g. '/static/premium-bg.svg').
    """
    os.makedirs(static_dir, exist_ok=True)
    dest = os.path.join(static_dir, BACKGROUND_FILENAME)
    with open(dest, "w") as fh:
        fh.write(_SVG)
    return BACKGROUND_URL
