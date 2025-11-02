# Simple Python script to create a 192x192 blue circle icon
from PIL import Image, ImageDraw
import base64
from io import BytesIO

# Create a 192x192 image with transparent background
img = Image.new('RGBA', (192, 192), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Draw a blue circle
draw.ellipse([24, 24, 168, 168], fill='#0ea5e9', outline='#0ea5e9')

# Draw a white inner circle
draw.ellipse([64, 64, 128, 128], fill='white', outline='white')

# Draw a smaller blue circle in center
draw.ellipse([80, 80, 112, 112], fill='#0ea5e9', outline='#0ea5e9')

# Save as PNG
buffer = BytesIO()
img.save(buffer, format='PNG')
png_data = buffer.getvalue()

# Save to file
with open('icon-192x192.png', 'wb') as f:
    f.write(png_data)

print("192x192 icon created successfully!")