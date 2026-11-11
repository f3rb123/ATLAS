"""A dotted skunk constellation shared by the terminal and the live dashboard."""

POINTS = [
    (5, 1), (8, 0), (11, 1), (13, 3), (13, 5), (12, 7), (10, 8),
    (7, 7), (5, 5), (5, 3), (7, 2), (9, 3), (10, 5), (9, 6),
    (8, 8), (10, 10), (13, 11), (16, 11), (19, 10), (21, 9),
    (22, 10), (23, 11), (22, 12), (20, 12), (18, 13), (15, 13),
    (12, 13), (9, 12), (7, 10), (6, 8), (10, 14), (11, 15),
    (17, 14), (18, 15), (20, 10), (18, 11), (16, 12), (13, 12),
]
PALETTE = ("#77e6df", "#a899ff", "#ed9bc4", "#eaca88")


def terminal(frame=0):
    from rich.text import Text
    result = Text()
    occupied = {point: index for index, point in enumerate(POINTS)}
    for y in range(16):
        for x in range(25):
            if (x, y) in occupied:
                index = occupied[(x, y)]
                result.append("● " if (index + frame) % 7 == 0 else "· ", style=PALETTE[(index // 4 + frame // 3) % len(PALETTE)])
            else:
                result.append("  ")
        result.append("\n")
    result.append("            S K U N K", style="bold white")
    result.append("\n      scoped intelligence · shared evidence", style="dim")
    return result


def svg():
    nodes = []
    for i, (x, y) in enumerate(POINTS):
        nodes.append(f'<circle cx="{x * 6 + 4}" cy="{y * 6 + 4}" r="1.7" fill="{PALETTE[i % 4]}" style="animation-delay:-{i % 9 / 4}s"/>')
        if i and i not in (14, 30, 32, 34):
            px, py = POINTS[i - 1]
            nodes.append(f'<line x1="{px * 6 + 4}" y1="{py * 6 + 4}" x2="{x * 6 + 4}" y2="{y * 6 + 4}" stroke="{PALETTE[i % 4]}" stroke-opacity=".36" stroke-width=".65"/>')
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 150 102" role="img" aria-label="SKUNK constellation"><style>circle{animation:pulse 2.8s infinite alternate}g{transform-origin:center;animation:drift 5s infinite alternate}@keyframes pulse{from{opacity:.35}to{opacity:1}}@keyframes drift{from{transform:rotate(-2deg)}to{transform:rotate(2deg)}}@media(prefers-reduced-motion:reduce){circle,g{animation:none}}</style><g>' + ''.join(nodes) + '</g></svg>'
